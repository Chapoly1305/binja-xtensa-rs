# Lifter quirks: core module (`lift/core.rs`)

Oddities in the reference `lifter.py` (core architecture, lines 146-773, and
boolean / miscellaneous operations, lines 1275-1469) that the port reproduces
on purpose. Each entry gives the encoding, what Python does, and why it looks
wrong. None of these is "fixed": the goal is byte-identical LLIL.

## CLAMPS writes to a register named by an expression index

- Encoding: CLAMPS `ar, as, imm` (`imm = t + 7`).
- Python: `ar_reg = il.reg(4, _reg_name(insn, "ar"))` is an `ExpressionIndex`,
  then `il.set_reg(4, ar_reg, ...)` three times. `Architecture.get_reg_index`
  passes an `int` through unchanged, so the destination register id is the
  expression index of the `LLIL_REG` expression, not `ar`.
- Why it looks wrong: the clamped value lands in whatever register has that
  numeric id (it depends on how many expressions the window-check prefix
  created). Port: `R(ar_reg as u32)`.

## SEXT writes `at` instead of `ar`

- Encoding: SEXT `ar, as, imm` (`imm = t + 7`).
- Python: computes `(as << (31 - b)) >>a (31 - b)` with `b = inline0 = t + 7`
  and stores it with `set_reg(4, _reg_name(insn, "at"), ...)`. It also builds
  an unused `il.reg(4, ar)` expression.
- Why it looks wrong: the ISA destination is `ar`; `t` is part of the
  immediate. The unused expression is kept so expression numbering matches.

## ALL4/ALL8/ANY4/ANY8 set a 1-byte boolean register with size 2

- Python `_lift_anyall`: `il.set_reg(2, _reg_name(insn, "bt"), temp)` where
  `temp` is a chain of 1-byte `and`/`or` over `bs .. bs+n-1`.
- The loop is `range(s + 1, min(s + offset, 16))`, so an unaligned `s` (the
  ISA requires `s` aligned to 4/8) silently truncates at `b15` instead of
  wrapping or faulting.

## BBC / BBS test the whole `at` register

- Python passes `il.reg(4, at)` as the bit index of `test_bit`, not
  `at & 31` (the reference comment acknowledges this).

## BF / BT do not use address labels

- `_lift_BFT` always creates two fresh `LowLevelILLabel`s and emits
  `if; jump(target)` without consulting `get_label_for_address`, unlike every
  other conditional branch (which goes through `_lift_cond` and also emits a
  fall-through `jump` when no label exists). Ported as is.

## S32I.N builds the source register name by hand

- Python uses `"a" + str(insn.t)` instead of `_reg_name(insn, "at")`. Same
  result for every decodable encoding (`t` is always set); for a `None`
  field the name would be `"aNone"`, which `get_reg_index` rejects. Ported as
  `Raise::NoSuchRegister` in that (unreachable) case.

## EXTUI skips the shift when `shiftimm` is falsy

- `if shiftimm:` treats both `0` and `None` as "no shift"; only the `0` case
  is reachable. Ported with a `Some(v) if v != 0` match.

## Constant sizes mix 1 and 4 bytes

- ABS shifts a 4-byte value by `const(1, 31)`, SLLI by `const(1, sa)`,
  EXTUI by `const(1, shiftimm)`, while SRAI/SRLI/SEXT use 4-byte shift
  constants. SLL computes `sub(1, const(1, 32), reg(1, sar))`. Kept exactly.

## L32R takes the address as 32 bits

- `insn.mem_offset(addr)` is arbitrary precision in Python; the Rust decoder
  API takes `u32`, so the port passes `addr as u32`. Identical for every
  32-bit address (all Xtensa addresses, and both oracle addresses).

## Aliases

- `_lift_BBCI_L = _lift_BBCI`, `_lift_BBSI_L = _lift_BBSI`,
  `_lift_BEQZ_N = _lift_BEQZ`, `_lift_BNEZ_N = _lift_BNEZ`,
  `_lift_NOP_N = _lift_NOP`, `_lift_ALL4 = _lift_ALL8 = _lift_ANY4 =
  _lift_ANY8 = _lift_anyall`; `_lift_MOVF`/`_lift_MOVT` are lambdas over
  `_lift_MOVFT(..., float=False)`. `_lift_L32I_N` is a separate function in
  Python but emits the same expressions in the same order as `_lift_L32I`, so
  both names map to one port. `BBCI_L`/`BBSI_L` are not decoder mnemonics but
  are answered by `handler()` because they are Python handler names.
- `lift_movft` (`_lift_MOVFT`) and `lift_minmax` are `pub` so the
  floating-point module can reuse them (`_lift_MOVF_S`/`_lift_MOVT_S` call
  `_lift_MOVFT(insn, addr, il, bit, True)`).
