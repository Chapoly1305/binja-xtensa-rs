#!/usr/bin/env python3
"""Disassemble every 3-byte encoding with independent disassemblers.

Second-opinion oracles for the decoder: GNU objdump (with the core
configuration its toolchain was built for, e.g. Espressif's ESP32 build) and
LLVM's Xtensa backend. Each shard (third byte 0xhh, 65,536 encodings) is
assembled into one ELF with one symbol per 4-byte slot; both objdumps restart
decoding at every symbol, so each encoding is decoded on its own. Only the
first instruction after each symbol is kept.

Output: <out>/<tool>_hh.tsv, one line per encoding:
    <word:06x>\t<len>\t<mnemonic>\t<operands>
with len 0 and mnemonic INVALID when the tool does not decode it. Operands are
the tool's own text; branch targets are rewritten as `@<offset>` relative to
the instruction address (the slot address), and symbolic suffixes dropped.

GNU binutils selects the Xtensa core configuration at run time from
XTENSA_GNU_CONFIG (Espressif's unified toolchain ships one .so per chip);
pass one --gnu-config NAME=PATH per configuration to compare.

Usage: xref_dump.py --gnu-bin DIR [--gnu-prefix xtensa-esp-elf-]
                    [--gnu-config esp32=.../xtensa_esp32.so ...]
                    [--llvm-objdump llvm-objdump] --out DIR [--shards 0-255] [--jobs N]
"""
from __future__ import annotations

import argparse
import multiprocessing as mp
import os
import re
import subprocess
import tempfile
from pathlib import Path

# All Xtensa features LLVM knows; the decoder accepts the union.
LLVM_ATTRS = ",".join("+" + f for f in (
    "bool clamps coprocessor dcache debug density dfpaccel div32 exception extendedl32r fp "
    "highpriinterrupts highpriinterrupts-level3 highpriinterrupts-level4 highpriinterrupts-level5 "
    "highpriinterrupts-level6 highpriinterrupts-level7 interrupt loop mac16 minmax miscsr mul16 "
    "mul32 mul32high nsa prid regprotect rvector sext threadptr timers1 timers2 timers3 windowed"
).split())

SYM = re.compile(r"^[0-9a-f]+ <w([0-9a-f]{6})>:$")
# GNU:  "   4:\tf01d      \tretw.n"    LLVM: "       4: 1d f0        \tretw.n"
GNU_INSN = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f]+)\s*\t(\S+)\s*(.*)$")
LLVM_INSN = re.compile(r"^\s*([0-9a-f]+):((?: [0-9a-f]{2})+)\s*\t(\S+)\s*(.*)$")
GNU_TARGET = re.compile(r"\b([0-9a-f]+) <[^>]*>")
LLVM_TARGET = re.compile(r"\b0x([0-9a-f]+)\b")


def build_elf(gnu_as: str, words: list[int], work: Path, tag: str) -> Path:
    src = work / f"{tag}.S"
    with src.open("w") as f:
        f.write(".text\n")
        for w in words:
            b = w.to_bytes(3, "little")
            f.write(f"w{w:06x}:\n .byte {b[0]},{b[1]},{b[2]},0\n")
    obj = work / f"{tag}.o"
    subprocess.run([gnu_as, "-o", str(obj), str(src)], check=True)
    src.unlink()
    return obj


def run_tool(gnu_as, cmd, insn_re, target_re, env, words, work, tag) -> dict[int, str]:
    """Disassemble `words`; if the tool crashes, bisect down to the encodings
    that crash it and record those as CRASH."""
    obj = build_elf(gnu_as, words, work, tag)
    proc = subprocess.run([*cmd, str(obj)], capture_output=True, text=True, env=env)
    obj.unlink()
    if proc.returncode == 0:
        return parse(proc.stdout, insn_re, target_re)
    if len(words) == 1:
        return {words[0]: f"0\tCRASH\tsignal {-proc.returncode}" if proc.returncode < 0
                else f"0\tCRASH\texit {proc.returncode}"}
    mid = len(words) // 2
    got = run_tool(gnu_as, cmd, insn_re, target_re, env, words[:mid], work, tag + "a")
    got.update(run_tool(gnu_as, cmd, insn_re, target_re, env, words[mid:], work, tag + "b"))
    return got


def parse(text: str, insn_re: re.Pattern, target_re: re.Pattern) -> dict[int, str]:
    out: dict[int, str] = {}
    cur = None
    for line in text.splitlines():
        m = SYM.match(line)
        if m:
            cur = int(m.group(1), 16)
            continue
        if cur is None or cur in out:
            continue
        m = insn_re.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        raw = m.group(2).replace(" ", "")
        length = len(raw) // 2
        mnem, ops = m.group(3), m.group(4).strip()
        if mnem.startswith(".byte") or mnem in ("<unknown>", "unknown"):
            out[cur] = f"0\tINVALID\t"
            continue
        # Branch, call and L32R targets become offsets from the instruction.
        ops = target_re.sub(lambda t: f"@{int(t.group(1), 16) - addr}", ops)
        out[cur] = f"{length}\t{mnem}\t{ops}"
    return out


def shard(args):
    gnu_bin, prefix, configs, llvm_objdump, out, hi = args
    gnu_as = str(Path(gnu_bin) / f"{prefix}as")
    words = [(hi << 16) | lo for lo in range(1 << 16)]
    jobs = {
        f"gnu-{name}": ([str(Path(gnu_bin) / f"{prefix}objdump"), "-d"], GNU_INSN, GNU_TARGET,
                        {**os.environ, "XTENSA_GNU_CONFIG": path})
        for name, path in configs
    }
    jobs["llvm"] = ([llvm_objdump, "-d", "--triple=xtensa", f"--mattr={LLVM_ATTRS}"],
                    LLVM_INSN, LLVM_TARGET, None)
    with tempfile.TemporaryDirectory() as td:
        for tool, (cmd, insn_re, target_re, env) in jobs.items():
            got = run_tool(gnu_as, cmd, insn_re, target_re, env, words, Path(td), f"s{hi:02x}")
            lines = [f"{w:06x}\t" + got.get(w, "0\tINVALID\t") for w in words]
            (Path(out) / f"{tool}_{hi:02x}.tsv").write_text("\n".join(lines) + "\n")
    return hi


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gnu-bin", required=True)
    ap.add_argument("--gnu-prefix", default="xtensa-esp-elf-")
    ap.add_argument("--gnu-config", action="append", default=[], metavar="NAME=PATH")
    ap.add_argument("--llvm-objdump", default="llvm-objdump")
    ap.add_argument("--out", required=True)
    ap.add_argument("--shards", default="0-255")
    ap.add_argument("--jobs", type=int, default=os.cpu_count())
    a = ap.parse_args()
    lo, _, hi = a.shards.partition("-")
    shards = range(int(lo, 0), int(hi or lo, 0) + 1)
    Path(a.out).mkdir(parents=True, exist_ok=True)
    with mp.Pool(a.jobs) as pool:
        for s in pool.imap_unordered(shard, [(a.gnu_bin, a.gnu_prefix, [c.split("=", 1) for c in a.gnu_config], a.llvm_objdump, a.out, s)
                                          for s in shards]):
            pass


if __name__ == "__main__":
    main()
