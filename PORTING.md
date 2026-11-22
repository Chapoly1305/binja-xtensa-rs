# Porting the reference lifter

The native lifter is a function-by-function port of the reference Python
plugin (`binja_xtensa/lifter.py` and its helper modules). The goal is
byte-identical LLIL: same expressions, same operand order, same sizes, same
labels, same instruction count, for every encoding at every address. Fidelity
comes first; idiomatic rewrites that change the IL are bugs, even when the new
IL would be "better". Known oddities in the reference are reproduced and listed
in `crates/binja-xtensa/LIFTER_QUIRKS.md`.

## The builder

`crate::il::Il` mirrors the Python `LowLevelILFunction` builder method for
method (`il.and_expr`, `il.compare_signed_less_than`, `il.if_expr`, labels by
pointer, `il.intrinsic(outputs, intrinsic, params)` ...). A Python line

```python
il.append(il.set_reg(4, _reg_name(insn, "ar"), il.add(4, il.reg(4, _reg_name(insn, "as")), il.const(4, 1))))
```

becomes

```rust
let v = il.add(4, il.reg(4, rn(insn, "as")?), il.const_(4, 1));
il.append(il.set_reg(4, rn(insn, "ar")?, v));
```

**Evaluation order matters.** Every builder call appends an expression to the
core's expression table, and Python evaluates arguments left to right,
innermost first. Bind sub-expressions to locals in the same order Python
would evaluate them. Expression indices are not compared, but labels and
`if`/`goto` targets refer to instruction indices, and the order of `append`
calls is compared exactly.

Registers are ids, resolved with `crate::regs::reg("ps")?`,
`crate::regs::numbered("a", n)?` or `common::rn(insn, "at")?`
(`_reg_name`). Intrinsics with `crate::regs::intrinsic("memw")?`. These
return `Err(Raise::NoSuchRegister)` where Python's `get_reg_index` would
raise (for example `a16`).

Temporary registers: `crate::il::temp(n)` is `LLIL_TEMP(n)`.

## Exceptions

A Python exception escaping a lift function is not caught by Binary Ninja's
callback wrapper (it only catches `OSError`): the core sees a successful lift
of `len(data)` bytes and keeps the IL appended so far.
Model it with `Err(Raise::..)` at the same point, after the same appends. Use
`?` on every lookup that can raise in Python. `assert` failures, `KeyError`,
`TypeError` from `None` arithmetic: all are `Err(Raise::Other("<site>"))`.

## Dispatch

`lift::common::handler_for` reproduces `globals()["_lift_" + mnem.replace(".", "_")]`
(and the `mac_kind` override). Each module's `handler(name)` maps a Python
name to its port; the union over modules must equal the names in
`lift::tables::LIFT_HANDLER_NAMES` that are mnemonics, with no overlap. A
Python name defined more than once resolves to its last definition.

## Testing

`harness/il_dump.py` dumps info, text and LLIL for all 2^24 encodings at two
addresses, through the core (so exceptions and return values are observed the
way Binary Ninja observes them). Reference dumps from the Python plugin are
kept outside the repository; compare with `harness/compare.py REF CAND --only
'REGEX'`. "Done" means zero `llil` mismatches for the mnemonics you own on all
256 shards.
