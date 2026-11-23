#!/usr/bin/env python3
"""Whole-binary dump of functions, basic blocks, lifted IL and LLIL.

Run with Binary Ninja's Python (``bnpython3``) and a BN user directory that
contains exactly one Xtensa plugin registered as ``xtensa`` (the reference
Python plugin or the native one), so the same script produces the reference
and the candidate dump. ``fn_compare.py`` diffs two dumps by function.

The ELF is opened with the given load options and analysed to completion.
Then, for every function in address order::

    F <start> <name>
    B <start> <end>                     one per native basic block
    L <i> <addr> <text>  [<tree>]       lifted IL instruction i
    l <i> <addr> <text>  [<tree>]       LLIL instruction i

``<i>`` is the instruction index within the function's IL (labels and
``goto``/``if`` targets print as such indices); expression indices are
never printed. ``<tree>`` (``--trees``) is the expression tree with sizes,
register/intrinsic names and IL attributes, as in ``il_dump.py``. Header lines
start with ``#``; timing goes to the header and to stderr, and is ignored by
the comparison.

Usage: bnpython3 fn_dump.py ELF OUT [--options JSON|@FILE] [--workers N] [--trees]
                            [--add-functions ADDR,...|@FILE] [--entry-candidates]
OUT ending in ``.gz`` is gzip-compressed.
"""
from __future__ import annotations

import argparse
import gzip
import json
import sys
import time


def _operand(bn, op) -> str:
    if isinstance(op, bn.lowlevelil.LowLevelILInstruction):
        return _expr(bn, op)
    if isinstance(op, (list, tuple)):
        return "[" + ",".join(_operand(bn, o) for o in op) + "]"
    if isinstance(op, dict):
        items = sorted(op.items(), key=lambda kv: str(kv[0]))
        return "{" + ",".join(f"{_operand(bn, k)}:{_operand(bn, v)}" for k, v in items) + "}"
    name = getattr(op, "name", None)
    if name is not None and not isinstance(op, int):
        return str(name)
    return str(op)


def _expr(bn, e) -> str:
    attrs = getattr(e, "attributes", None)
    tail = ("@" + "+".join(sorted(a.name for a in attrs))) if attrs else ""
    return f"{e.operation.name}.{e.size}({','.join(_operand(bn, o) for o in e.operands)}){tail}"


def _il_lines(bn, tag: str, il, trees: bool):
    if il is None:
        yield f"{tag} NONE"
        return
    for i in range(len(il)):
        ins = il[i]
        line = f"{tag} {i} {ins.address:x} {ins}"
        if trees:
            line += "\t" + _expr(bn, ins)
        yield line


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("elf")
    ap.add_argument("out")
    ap.add_argument("--options", default="{}", help="load options as JSON, or @FILE")
    ap.add_argument("--workers", type=int, help="analysis.limits.workerThreadCount and set_worker_thread_count")
    ap.add_argument("--trees", action="store_true", help="also print expression trees")
    ap.add_argument("--arch", default="xtensa", help="architecture name the plugin must register")
    ap.add_argument("--entry-candidates", action="store_true",
                    help="before analysis, add a function at every 'ENTRY a1, n' encoding in executable segments")
    ap.add_argument("--add-functions", help="comma-separated start addresses (or @FILE) to add after loading")
    a = ap.parse_args()
    options = json.loads(open(a.options[1:]).read() if a.options.startswith("@") else a.options)

    import binaryninja as bn

    if bn.Architecture[a.arch] is None:
        raise SystemExit(f"architecture {a.arch!r} is not registered")
    if a.workers is not None:
        options["analysis.limits.workerThreadCount"] = a.workers
        bn.set_worker_thread_count(a.workers)

    t0 = time.monotonic()
    bv = bn.load(a.elf, options=options, update_analysis=not a.entry_candidates)
    if bv is None:
        raise SystemExit(f"could not open {a.elf}")
    if a.entry_candidates:
        # Byte-derived discovery as used in production for symbol-less images:
        # ENTRY is BRI12 with byte 0 = 0x36; s (low nibble of byte 1) = a1.
        candidates = set()
        for seg in bv.segments:
            if not seg.executable or not seg.data_length:
                continue
            data = bv.read(seg.start, seg.data_length)
            for off in range(len(data) - 2):
                if data[off] == 0x36 and data[off + 1] & 0xF == 1:
                    candidates.add(seg.start + off)
        for start in sorted(candidates):
            if bv.get_function_at(start) is None:
                bv.add_function(start, auto_discovered=True)
        print(f"entry_candidates {len(candidates)}", file=sys.stderr, flush=True)
    if a.add_functions:
        spec = open(a.add_functions[1:]).read() if a.add_functions.startswith("@") else a.add_functions
        for start in (int(x, 0) for x in spec.replace("\n", ",").split(",") if x.strip()):
            bv.add_function(start)
    bv.update_analysis_and_wait()
    analysis = time.monotonic() - t0
    print(f"analysis_seconds {analysis:.1f}", file=sys.stderr, flush=True)

    workflows = sorted(w.name for w in bn.Workflow if "xtensa" in w.name)
    settings = bn.Settings()
    funcs = sorted(bv.functions, key=lambda f: (f.start, f.arch.name if f.arch else ""))
    opener = gzip.open if a.out.endswith(".gz") else open
    t1 = time.monotonic()
    with opener(a.out, "wt", encoding="utf-8") as out:
        out.write(f"# elf {a.elf}\n")
        out.write(f"# options {json.dumps(options, sort_keys=True)}\n")
        out.write(f"# workflows {','.join(workflows)}\n")
        for key in ("analysis.workflows.functionWorkflow", "arch.xtensa.windowVectorProfile", "arch.xtensa.depcPresence"):
            try:
                value = settings.get_string(key, bv)
            except Exception as exc:  # setting not registered
                value = f"<{type(exc).__name__}>"
            out.write(f"# setting {key} {value}\n")
        out.write(f"# functions {len(funcs)}\n")
        out.write(f"# analysis_seconds {analysis:.1f}\n")
        for f in funcs:
            out.write(f"F {f.start:x} {f.name} {f.arch.name if f.arch else '-'}\n")
            for b in sorted(f.basic_blocks, key=lambda b: b.start):
                out.write(f"B {b.start:x} {b.end:x}\n")
            for line in _il_lines(bn, "L", f.lifted_il, a.trees):
                out.write(line + "\n")
            llil = f.llil_if_available
            for line in _il_lines(bn, "l", llil, a.trees):
                out.write(line + "\n")
    print(f"dump_seconds {time.monotonic() - t1:.1f}", file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
