#!/usr/bin/env python3
"""Compare two fn_dump.py outputs function by function.

Usage: fn_compare.py REF CAND [--show N] [--context N] [--unimpl-attribution] [--text-only] [--list]
                     [--normalize-jump-to]

Prints the header lines of both dumps, the function sets, and per section
(``name``, ``blocks``, ``lifted``, ``llil``) the number of functions that
differ, followed by a unified diff of the first N differing functions.

With ``--unimpl-attribution``, a function whose lifted IL differs is
attributed to the per-instruction lifter when the candidate's lifted IL has
``unimplemented`` at an address where the reference's has none (the case of a
stubbed lifter module); such functions are counted separately, and the
remaining ones are the differences to explain.
"""
from __future__ import annotations

import argparse
import collections
import difflib
import gzip
import re
import sys

SECTIONS = ("name", "blocks", "lifted", "llil")


# A constant jump whose only target is that constant: Binary Ninja lifts it as
# jump(c) or as jump_to(c, {c: i}) depending on analysis order (it varies
# between runs of the same plugin with different worker counts).
_JT_TEXT = re.compile(r"jump\((0x[0-9a-f]+) => \d+(?: @ \1)?\)")
_JT_TREE = re.compile(r"LLIL_JUMP_TO\.0\(LLIL_CONST\.4\((\d+)\),\{\1:\d+\}\)")


def normalize_jump_to(line):
    line = _JT_TEXT.sub(r"jump(\1)", line)
    return _JT_TREE.sub(r"LLIL_JUMP.0(LLIL_CONST.4(\1))", line)


def load(path, text_only=False, norm=False):
    opener = gzip.open if path.endswith(".gz") else open
    header, funcs, cur = [], {}, None
    with opener(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if text_only:
                line = line.split("\t", 1)[0]
            if norm:
                line = normalize_jump_to(line)
            if line.startswith("#"):
                header.append(line)
                continue
            tag = line[:1]
            if tag == "F":
                _, start, rest = line.split(" ", 2)
                cur = {"name": [rest], "blocks": [], "lifted": [], "llil": []}
                funcs[start] = cur
            elif tag == "B":
                cur["blocks"].append(line)
            elif tag == "L":
                cur["lifted"].append(line)
            elif tag == "l":
                cur["llil"].append(line)
    return header, funcs


def unimpl_addrs(lines):
    out = set()
    for line in lines:
        parts = line.split(" ", 3)
        if len(parts) == 4 and parts[3].split("\t", 1)[0] == "unimplemented":
            out.add(parts[2])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ref")
    ap.add_argument("cand")
    ap.add_argument("--show", type=int, default=3, help="functions to diff in full")
    ap.add_argument("--context", type=int, default=3)
    ap.add_argument("--max-lines", type=int, default=60, help="diff lines shown per function")
    ap.add_argument("--unimpl-attribution", action="store_true")
    ap.add_argument("--normalize-jump-to", action="store_true",
                    help="treat jump(c) and jump_to(c, {c: i}) as equal (analysis-order dependent)")
    ap.add_argument("--text-only", action="store_true", help="ignore expression trees (compare dumps made with and without --trees)")
    ap.add_argument("--list", action="store_true", help="list every differing function and section")
    a = ap.parse_args()
    rh, ref = load(a.ref, a.text_only, a.normalize_jump_to)
    ch, cand = load(a.cand, a.text_only, a.normalize_jump_to)
    print("reference header:")
    for h in rh:
        print("   ", h)
    print("candidate header:")
    for h in ch:
        print("   ", h)
    only_ref = sorted(set(ref) - set(cand), key=lambda s: int(s, 16))
    only_cand = sorted(set(cand) - set(ref), key=lambda s: int(s, 16))
    common = sorted(set(ref) & set(cand), key=lambda s: int(s, 16))
    print(f"functions: ref {len(ref)}, cand {len(cand)}, common {len(common)}, "
          f"only ref {len(only_ref)}, only cand {len(only_cand)}")
    for s in only_ref[:20]:
        print(f"  only ref  {s} {ref[s]['name'][0]}")
    for s in only_cand[:20]:
        print(f"  only cand {s} {cand[s]['name'][0]}")
    differ = collections.Counter()
    differing = []
    attributed = []
    for s in common:
        bad = [k for k in SECTIONS if ref[s][k] != cand[s][k]]
        if not bad:
            continue
        for k in bad:
            differ[k] += 1
        if a.unimpl_attribution and (unimpl_addrs(cand[s]["lifted"]) - unimpl_addrs(ref[s]["lifted"])):
            attributed.append((s, bad))
        else:
            differing.append((s, bad))
    identical = len(common) - len(differing) - len(attributed)
    print(f"identical functions: {identical}/{len(common)}")
    for k in SECTIONS:
        print(f"  {k:7s} differs in {differ[k]}")
    if a.unimpl_attribution:
        print(f"attributed to unimplemented lifting in the candidate: {len(attributed)}")
        print(f"unattributed differences: {len(differing)}")
    if a.list:
        for s, bad in attributed:
            print(f"  A {s} {ref[s]['name'][0]} {','.join(bad)}")
        for s, bad in differing:
            print(f"  D {s} {ref[s]['name'][0]} {','.join(bad)}")
    for s, bad in differing[: a.show]:
        print(f"\n=== {s} {ref[s]['name'][0]}: {','.join(bad)}")
        for k in bad:
            diff = list(difflib.unified_diff(ref[s][k], cand[s][k], f"ref/{k}", f"cand/{k}", n=a.context, lineterm=""))
            for line in diff[: a.max_lines]:
                print(line)
            if len(diff) > a.max_lines:
                print(f"... {len(diff) - a.max_lines} more diff lines")
    return 0 if not (only_ref or only_cand or differing) else 1


if __name__ == "__main__":
    sys.exit(main())
