#!/usr/bin/env python3
"""Dump instruction info, text and LLIL for every 3-byte encoding, inside Binary Ninja.

Run with Binary Ninja's Python (``bnpython3``) and a licensed install. The
architecture is chosen by name, so the same script produces the reference dump
from the Python plugin (``--arch xtensa``) and the candidate dump from the
native plugin (registered under another name for side-by-side runs, see
``XTENSA_RS_ARCH_NAME``). The two dumps are compared shard by shard with
``compare.py``; nothing in the format depends on which plugin produced it,
except the architecture name, which is never printed.

Each encoding is evaluated at the same two addresses as the decode oracle.
Lines are:

    <word>\t<addr>\tNONE
    <word>\t<addr>\t<len>\t<branches>\t<tokens>\t<llil_len>\t<il>

``<il>`` is every LLIL instruction appended by the lift, serialized as an
expression tree with register, flag and intrinsic names (never indices, which
differ between plugins), joined by ``;``.

Usage: bnpython3 il_dump.py --arch NAME --out DIR [--shards 0-255] [--jobs N]
"""
from __future__ import annotations

import argparse
import hashlib
import multiprocessing as mp
import os
import sys
from pathlib import Path

ADDRS = (0x40080000, 0x400D1233)

_arch = None
_bn = None


def _init(arch_name: str) -> None:
    global _arch, _bn
    import binaryninja as bn

    _bn = bn
    _arch = bn.Architecture[arch_name]
    if _arch is None:
        raise SystemExit(f"architecture {arch_name!r} is not registered")


def _operand(op) -> str:
    bn = _bn
    if isinstance(op, bn.lowlevelil.LowLevelILInstruction):
        return _expr(op)
    if isinstance(op, (list, tuple)):
        return "[" + ",".join(_operand(o) for o in op) + "]"
    if isinstance(op, dict):
        return "{" + ",".join(f"{_operand(k)}:{_operand(v)}" for k, v in sorted(op.items(), key=lambda kv: str(kv[0]))) + "}"
    name = getattr(op, "name", None)
    if name is not None and not isinstance(op, int):
        return str(name)
    return str(op)


def _expr(e) -> str:
    attrs = getattr(e, "attributes", None)
    tail = ("@" + "+".join(sorted(a.name for a in attrs))) if attrs else ""
    return f"{e.operation.name}.{e.size}({','.join(_operand(o) for o in e.operands)}){tail}"


def line_for(word: int, addr: int) -> str:
    bn = _bn
    data = word.to_bytes(3, "little")
    head = f"{word:06x}\t{addr:08x}"
    info = _arch.get_instruction_info(data, addr)
    if info is None:
        return f"{head}\tNONE"
    branches = ",".join(
        f"{b.type.name}:{'-' if b.target is None else format(b.target, 'x')}" for b in info.branches
    )
    text = _arch.get_instruction_text(data, addr)
    if text is None:
        toks = "NONE"
    else:
        tokens, tlen = text
        toks = f"{tlen}#" + "|".join(f"{t.type.name}:{t.text}:{t.value}:{t.size}" for t in tokens)
    il = bn.lowlevelil.LowLevelILFunction(_arch)
    n = _arch.get_instruction_low_level_il(data, addr, il)
    body = ";".join(_expr(il[i]) for i in range(len(il)))
    return f"{head}\t{info.length}\t{branches}\t{toks}\t{n}\t{body}"


def _shard(args):
    arch_name, out, hi = args
    if _arch is None:
        _init(arch_name)
    lines = [line_for((hi << 16) | lo, a) for lo in range(1 << 16) for a in ADDRS]
    data = ("\n".join(lines) + "\n").encode()
    (Path(out) / f"il_{hi:02x}.tsv").write_bytes(data)
    return hi, hashlib.sha256(data).hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--arch", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--jobs", type=int, default=os.cpu_count())
    ap.add_argument("--shards", default="0-255")
    a = ap.parse_args()
    lo, _, hi = a.shards.partition("-")
    shards = list(range(int(lo, 0), int(hi or lo, 0) + 1))
    Path(a.out).mkdir(parents=True, exist_ok=True)
    # Each worker initialises its own Binary Ninja core; fork after import would
    # share one core between processes, which BN does not support.
    ctx = mp.get_context("spawn")
    with ctx.Pool(a.jobs) as pool:
        for hi_, digest in pool.imap_unordered(_shard, [(a.arch, a.out, s) for s in shards]):
            print(f"{digest}  il_{hi_:02x}.tsv", flush=True)


if __name__ == "__main__":
    sys.exit(main())
