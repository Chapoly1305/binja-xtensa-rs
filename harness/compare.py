#!/usr/bin/env python3
"""Compare two il_dump.py outputs shard by shard.

Usage: compare.py REF_DIR CAND_DIR [--cols info,text,llil] [--show N] [--shards 0-255] [--only REGEX]

Columns: info = length + branches, text = tokens, llil = return value + IL.
Prints per-column mismatch counts, the mnemonics most affected, and the first
N mismatching lines per column.
"""
import argparse
import collections
from pathlib import Path

COLS = {"info": (2, 3), "text": (4,), "llil": (5, 6)}


def fields(line):
    f = line.rstrip("\n").split("\t")
    if len(f) == 3:  # NONE
        return f[:2], {"info": ("NONE",), "text": ("NONE",), "llil": ("NONE",)}, None
    mnem = f[4].split("#", 1)[1].split("|", 1)[0].split(":")[1] if "#" in f[4] else "?"
    return f[:2], {k: tuple(f[i] for i in idx) for k, idx in COLS.items()}, mnem


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ref")
    ap.add_argument("cand")
    ap.add_argument("--cols", default="info,text,llil")
    ap.add_argument("--show", type=int, default=3)
    ap.add_argument("--shards", default="0-255")
    ap.add_argument("--only", help="regex: compare only lines whose reference mnemonic matches")
    a = ap.parse_args()
    import re
    only = re.compile(a.only) if a.only else None
    cols = a.cols.split(",")
    lo, _, hi = a.shards.partition("-")
    bad = collections.Counter()
    by_mnem = {c: collections.Counter() for c in cols}
    shown = collections.Counter()
    total = 0
    for s in range(int(lo, 0), int(hi or lo, 0) + 1):
        rp, cp = Path(a.ref) / f"il_{s:02x}.tsv", Path(a.cand) / f"il_{s:02x}.tsv"
        if not rp.exists() or not cp.exists():
            continue
        with rp.open() as r, cp.open() as c:
            for lr, lc in zip(r, c):
                total += 1
                kr, fr, mr = fields(lr)
                kc, fc, _ = fields(lc)
                assert kr == kc, (kr, kc)
                if only and not (mr and only.fullmatch(mr)):
                    continue
                for col in cols:
                    if fr[col] != fc[col]:
                        bad[col] += 1
                        by_mnem[col][mr or "NONE"] += 1
                        if shown[col] < a.show:
                            shown[col] += 1
                            print(f"--- {col} {kr[0]} @{kr[1]} ({mr})\n  ref:  {fr[col]}\n  cand: {fc[col]}")
    print(f"\n{total} lines compared")
    for col in cols:
        print(f"{col}: {bad[col]} mismatches; top mnemonics {by_mnem[col].most_common(12)}")


main()
