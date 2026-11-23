#!/usr/bin/env python3
"""Compare the reference decoder's oracle with independent disassemblers.

Inputs: the decode oracle shards from gen_golden.py (or the `golden` example)
and the xref_dump.py shards. Each side is reduced to (length, mnemonic,
operands), with:

* mnemonics lower-cased;
* operands split on commas, integers parsed (decimal or 0x), and branch /
  call / L32R targets as offsets from the instruction (`@N`); the reference
  text is taken at its first oracle address, 0x40080000, which is 4-aligned
  like the dump slots, so L32R/CALL alignment agrees;
* special/user register forms unified: `rsr.lbeg a2`, `rsr a2, lbeg` and
  `RSR.LBEG a2` all become `rsr a2,lbeg` (the reference prints unknown ones as
  numbers, which stay numbers);
* an instruction the reference marks invalid, or a tool cannot decode, is
  `INVALID`.

Usage: xref_compare.py GOLDEN_DIR XREF_DIR --tools gnu-esp32,gnu-esp32s3,llvm
                       [--out report.tsv] [--examples N] [--jobs N]
Writes one row per (tool, reference mnemonic, outcome) with counts and
example encodings, and prints a summary.
"""
from __future__ import annotations

import argparse
import collections
import multiprocessing as mp
import os
import re
from pathlib import Path

REF_ADDR = 0x40080000
SR_OPS = ("rsr", "wsr", "xsr", "rur", "wur")
INT = re.compile(r"^-?(0x[0-9a-f]+|\d+)$")


def norm_operand(op: str):
    op = op.strip().lower()
    if op.startswith("@"):
        return op
    if INT.match(op):
        return int(op, 0)
    return op


def normalize(length: int, mnem: str, ops: list):
    mnem = mnem.lower()
    head, dot, tail = mnem.partition(".")
    if head in SR_OPS and dot:
        # rsr.lbeg a2  ->  rsr a2,lbeg (named or numbered register)
        ops = ops + [norm_operand(tail)]
        mnem = head
    return (length, mnem, tuple(ops))


def ref_line(line: str):
    f = line.rstrip("\n").split("\t")
    word = int(f[0], 16)
    if f[1].startswith("EXC") or f[1] == "NONE" or f[2] != "V":
        return word, "INVALID", None
    length, mnem = int(f[1]), f[3]
    toks = [t.split(":", 3) for t in f[7].split("|")]
    ops = []
    for kind, text, value, size in toks[1:]:
        if kind in ("text", "sep"):
            continue
        if kind == "addr":
            ops.append(f"@{int(text, 16) - REF_ADDR}")
        else:
            ops.append(norm_operand(text))
    return word, mnem.lower(), normalize(length, mnem, ops)


def tool_line(line: str):
    f = line.rstrip("\n").split("\t")
    word, length, mnem = int(f[0], 16), int(f[1]), f[2]
    if mnem in ("INVALID", "CRASH"):
        return word, mnem, None
    ops_text = f[3] if len(f) > 3 else ""
    ops = [norm_operand(o) for o in ops_text.split(",")] if ops_text.strip() else []
    return word, mnem.lower(), normalize(length, mnem, ops)


def outcome(ref, tool) -> str:
    _, rm, rn = ref
    _, tm, tn = tool
    if tm == "CRASH":
        return "tool_crash"
    if rn is None and tn is None:
        return "both_invalid"
    if rn is None:
        return "ref_invalid_tool_decodes"
    if tn is None:
        return "tool_invalid_ref_decodes"
    if rn == tn:
        return "agree"
    if rn[1] != tn[1]:
        return "mnemonic"
    if rn[0] != tn[0]:
        return "length"
    if len(rn[2]) != len(tn[2]):
        return "operand_count"
    return "operand_value"


def one_shard(args):
    golden, xref, tools, hi, examples = args
    counts = collections.Counter()
    ex = collections.defaultdict(list)
    ref = [ref_line(l) for l in open(Path(golden) / f"shard_{hi:02x}.tsv")]
    for tool in tools:
        for r, l in zip(ref, open(Path(xref) / f"{tool}_{hi:02x}.tsv")):
            t = tool_line(l)
            assert r[0] == t[0]
            o = outcome(r, t)
            key = (tool, r[1], o, t[1] if o in ("mnemonic", "ref_invalid_tool_decodes") else "")
            counts[key] += 1
            if o not in ("agree", "both_invalid") and len(ex[key]) < examples:
                ex[key].append(f"{r[0]:06x}: ref={r[2]} {tool}={t[2] if t[2] else t[1]}")
    return counts, ex


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("golden")
    ap.add_argument("xref")
    ap.add_argument("--tools", default="gnu-esp32,gnu-esp32s3,llvm")
    ap.add_argument("--out", default="xref_report.tsv")
    ap.add_argument("--examples", type=int, default=3)
    ap.add_argument("--shards", default="0-255")
    ap.add_argument("--jobs", type=int, default=os.cpu_count())
    a = ap.parse_args()
    tools = a.tools.split(",")
    lo, _, hi = a.shards.partition("-")
    shards = range(int(lo, 0), int(hi or lo, 0) + 1)
    counts = collections.Counter()
    ex = collections.defaultdict(list)
    with mp.Pool(a.jobs) as pool:
        for c, e in pool.imap_unordered(one_shard, [(a.golden, a.xref, tools, s, a.examples) for s in shards]):
            counts.update(c)
            for k, v in e.items():
                ex[k].extend(v[: a.examples - len(ex[k])])
    with open(a.out, "w") as f:
        f.write("tool\tref_mnemonic\toutcome\ttool_mnemonic\tcount\texamples\n")
        for key, n in sorted(counts.items(), key=lambda kv: (kv[0][0], -kv[1])):
            f.write("\t".join([*key, str(n), " ; ".join(ex.get(key, []))]) + "\n")
    for tool in tools:
        per = collections.Counter()
        for (t, _, o, _), n in counts.items():
            if t == tool:
                per[o] += n
        total = sum(per.values())
        print(f"{tool}: " + ", ".join(f"{o} {n} ({100 * n / total:.2f}%)" for o, n in per.most_common()))


if __name__ == "__main__":
    main()
