#!/usr/bin/env python3
"""Dump an architecture's static model (registers, stacks, intrinsics, calling
conventions) as JSON, by name, so the native plugin's tables can be generated
from and checked against the reference plugin. Run with bnpython3."""
import json
import sys

import binaryninja as bn

arch = bn.Architecture[sys.argv[1]]
regs = []
for name in arch.regs:
    info = arch.regs[name]
    regs.append({"name": name, "index": int(arch.get_reg_index(name)), "full_width": info.full_width_reg,
                 "size": info.size, "offset": info.offset, "extend": info.extend.name})
regs.sort(key=lambda r: r["index"])
model = {
    "name": arch.name, "address_size": arch.address_size, "default_int_size": arch.default_int_size,
    "max_instr_length": arch.max_instr_length, "instr_alignment": arch.instr_alignment,
    "endianness": arch.endianness.name, "stack_pointer": arch.stack_pointer, "link_reg": arch.link_reg,
    "global_regs": list(arch.global_regs), "system_regs": list(getattr(arch, "system_regs", [])),
    "regs": regs,
    "reg_stacks": {n: {"storage": list(s.storage_regs), "top_relative": list(s.top_relative_regs),
                       "stack_top": s.stack_top_reg} for n, s in arch.reg_stacks.items()},
    "flags": list(arch.flags),
    "intrinsics": {n: {"inputs": [[str(i.type), i.name] for i in v.inputs], "outputs": [str(o) for o in v.outputs]}
                   for n, v in arch.intrinsics.items()},
    "intrinsic_order": [n for n in sorted(arch.intrinsics, key=lambda n: int(arch.get_intrinsic_index(n)))],
    "calling_conventions": {},
}
for n, cc in arch.calling_conventions.items():
    model["calling_conventions"][n] = {k: getattr(cc, k) for k in (
        "caller_saved_regs", "callee_saved_regs", "int_arg_regs", "float_arg_regs", "int_return_reg",
        "high_int_return_reg", "float_return_reg", "global_pointer_reg", "implicitly_defined_regs",
        "arg_regs_share_index", "arg_regs_for_varargs", "stack_reserved_for_arg_regs",
        "stack_adjusted_on_return", "eligible_for_heuristics")}
model["default_calling_convention"] = arch.standalone_platform.default_calling_convention.name
json.dump(model, sys.stdout, indent=1, default=str)
