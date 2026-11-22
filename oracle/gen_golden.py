#!/usr/bin/env python3
"""Generate the exhaustive decode/disassembly oracle from the Python plugin.

Runs the reference Python decoder (``instruction.py`` + ``disassembly.py``) on
every one of the 2**24 three-byte encodings, without Binary Ninja: the two BN
names that ``disassembly.py`` imports are replaced by a minimal stand-in. Output
is 256 shards (one per value of the third byte), one line per encoding, in the
canonical format that ``xtensa-isa``'s ``golden`` example also prints, plus
``short.tsv`` for 1- and 2-byte inputs (keyed by their little-endian hex). The
shards are compared byte for byte, so any formatting change has to be made on
both sides.

Usage: gen_golden.py --plugin-dir PATH/binja_xtensa --out DIR [--jobs N]
"""
from __future__ import annotations

import argparse
import enum
import hashlib
import importlib
import multiprocessing as mp
import os
import sys
import types
from pathlib import Path

ADDRS = (0x40080000, 0x400D1233)
FIELDS = ("op0", "op1", "op2", "r", "s", "sr", "t", "n", "m", "i", "z",
          "imm4", "imm6", "imm7", "imm8", "imm12", "imm16", "offset")


def _install_stub() -> None:
    bn = types.ModuleType("binaryninja")
    enums = types.ModuleType("binaryninja.enums")

    class InstructionTextTokenType(enum.Enum):
        TextToken = "text"
        InstructionToken = "insn"
        OperandSeparatorToken = "sep"
        RegisterToken = "reg"
        IntegerToken = "int"
        PossibleAddressToken = "addr"

    class InstructionTextToken:
        __slots__ = ("type", "text", "value", "size")

        def __init__(self, token_type, text, value=0, size=0, *_, **__):
            self.type, self.text, self.value, self.size = token_type, text, value, size

    bn.InstructionTextToken = InstructionTextToken
    enums.InstructionTextTokenType = InstructionTextTokenType
    bn.enums = enums
    sys.modules["binaryninja"] = bn
    sys.modules["binaryninja.enums"] = enums


_insn = _dis = None


def _load(plugin_dir: str) -> None:
    global _insn, _dis
    _install_stub()
    pkg = types.ModuleType("xtensa_oracle")
    pkg.__path__ = [plugin_dir]  # import submodules without running __init__.py
    sys.modules["xtensa_oracle"] = pkg
    _insn = importlib.import_module("xtensa_oracle.instruction")
    _dis = importlib.import_module("xtensa_oracle.disassembly")


def _fmt_value(v) -> str:
    return "-" if v is None else str(v)


def line_for(word: int, nbytes: int = 3) -> str:
    raw = word.to_bytes(nbytes, "little")
    head = raw.hex() if nbytes != 3 else f"{word:06x}"
    try:
        insn = _insn.Instruction.decode(raw)
    except Exception as exc:  # noqa: BLE001 - the oracle's own failure is data
        return f"{head}\tEXC {type(exc).__name__}"
    if insn is None:
        return f"{head}\tNONE"
    itype = insn.instruction_type.name if insn.instruction_type is not None else "-"
    parts = [head, str(insn.length), "V" if insn.valid else "I",
             getattr(insn, "mnem", "-") or "-", itype,
             ",".join(f"{f}={getattr(insn, f)}" for f in FIELDS if getattr(insn, f) is not None)]
    inl = []
    for k in sorted(k for k in vars(insn) if k.startswith("inline")):
        vals = []
        for a in ADDRS:
            try:
                vals.append(_fmt_value(getattr(insn, k)(a)))
            except Exception as exc:  # noqa: BLE001
                vals.append(f"EXC:{type(exc).__name__}")
        inl.append(f"{k}=" + "/".join(vals))
    parts.append(",".join(inl))
    for a in ADDRS:
        try:
            toks = _dis.disassemble_instruction(insn, a)
        except Exception as exc:  # noqa: BLE001
            parts.append(f"EXC:{type(exc).__name__}")
            continue
        if toks is None:
            parts.append("NONE")
            continue
        parts.append("|".join(f"{t.type.value}:{t.text}:{t.value}:{t.size}" for t in toks))
    return "\t".join(parts)


def _shard(args):
    plugin_dir, out, hi = args
    if _insn is None:
        _load(plugin_dir)
    path = Path(out) / f"shard_{hi:02x}.tsv"
    lines = [line_for((hi << 16) | lo) for lo in range(1 << 16)]
    data = ("\n".join(lines) + "\n").encode()
    path.write_bytes(data)
    return hi, hashlib.sha256(data).hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--plugin-dir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--jobs", type=int, default=os.cpu_count())
    ap.add_argument("--shards", default="0-255", help="e.g. 0-255 or 7")
    a = ap.parse_args()
    lo, _, hi = a.shards.partition("-")
    shards = range(int(lo), int(hi or lo) + 1)
    Path(a.out).mkdir(parents=True, exist_ok=True)
    with mp.Pool(a.jobs) as pool:
        digests = dict(pool.imap_unordered(_shard, [(a.plugin_dir, a.out, s) for s in shards]))
    if _insn is None:
        _load(a.plugin_dir)
    # Short inputs: BN passes fewer than three bytes at the end of a segment.
    # Lines are keyed by the little-endian byte string (1 or 2 bytes).
    short = [line_for(w, 1) for w in range(1 << 8)] + [line_for(w, 2) for w in range(1 << 16)]
    data = ("\n".join(short) + "\n").encode()
    (Path(a.out) / "short.tsv").write_bytes(data)
    digests["short"] = hashlib.sha256(data).hexdigest()
    with open(Path(a.out) / "SHA256SUMS", "w") as f:
        for s in sorted(k for k in digests if k != "short"):
            f.write(f"{digests[s]}  shard_{s:02x}.tsv\n")
        f.write(f"{digests['short']}  short.tsv\n")


if __name__ == "__main__":
    main()
