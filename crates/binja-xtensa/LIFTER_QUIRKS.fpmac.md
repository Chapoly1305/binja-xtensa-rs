# Lifter quirks: FP coprocessor, loops, exceptions, MAC16, cache/TLB

Reference behaviours reproduced on purpose by `src/lift/fp_mac.rs` and
`src/lift/fp_mac/general_exception.rs` (ports of `lifter.py` lines
1062-1274 and 1470-1825, and `general_exception.py`). Each entry names the
reference site.

## Floating point

- `CEIL.S`, `FLOOR.S`, `ROUND.S` scale by `2**t` *before* rounding and
  write the rounded single straight into `ar` (`set_reg.4(ar, CEIL.4(FMUL ...))`):
  no float-to-int conversion node, no saturation. Only `TRUNC.S`/`UTRUNC.S`
  model NaN and saturation.
- `TRUNC.S`/`UTRUNC.S` (`_lift_trunc_s`) build `reg.4(temp30)` before
  assigning `temp30`, reuse that one expression five times, and compare
  with `or.1` of two float compares. The in-range path is
  `low_part.4(float_trunc.8(temp30))` (an 8-byte truncation of a 4-byte value).
  The lower bound is `<= -2147483648.0` for both variants, so `UTRUNC.S`
  of any value in (-2^31, 0) takes the "convert" path and wraps.
  A trailing `nop` is appended at the `done` label.
- `FLOAT.S` converts `as` as signed; `UFLOAT.S` zero-extends to 8 bytes
  first. Both scale by `float_const_single(2.0**-t)`.
- `OEQ.S`..`ULT.S` read `fs` and `ft` twice (two separate `reg` pairs).
  `UN.S` uses `float_compare_unordered` only.
- `MOVF.S`/`MOVT.S` go through `_lift_MOVFT` (Boolean Option section),
  which compares `reg.1(bt)` with `const.1(bit)`; ported locally as
  `movft`.

## Loops

- `LOOP`/`LOOPNEZ`/`LOOPGTZ` (`_lift_loop_instruction`) set
  `lcount = as - 1` (wraps for 0), `lbeg = addr + insn.length`,
  `lend = addr + 4 + imm8`. `LOOPNEZ` adds `if (as == 0)` and `LOOPGTZ`
  `if (as <= 0, signed)`, each jumping to `const_pointer(lend)`. The
  `reg.4(as)` expression is shared between the subtraction and the
  compare. No back-edge is lifted per instruction; the reference loop
  workflow (`loop_workflow.py`, separate port) installs
  `il._xtensa_conditional_handler` and rewrites loop ends at function
  scope. These lifters read no settings and no labels, so the
  per-instruction output (no view, default settings) is the full story here.
- `_lift_LOOP_simple` is unreachable from the dispatcher (no mnemonic
  `LOOP.simple`); it is ported as `lift_loop_simple` (dead code) for the
  workflow port. It uses `lbeg = addr + 3` and calls `set_current_address`.

## Exceptions and interrupts

- `ILL`, `ILL.N`, `RFUE` raise cause 0, `SYSCALL` cause 1, all with
  EPC = the instruction address (`raise_exception`). The double-exception
  arm duplicates `finish(..., 'doubleexception')` for the DEPC and EPC1
  arms. The reserved opcode slot (`ILL`, invalid) lifts the same way.
- `RFDE` (`double_return`) returns through `depc` or `epc1` depending on
  `config_ndepc`, and leaves PS untouched.
- `RFE` clears PS.EXCM (`and 0xffffffef`) and returns through `epc1`
  (no user/kernel distinction, no `RFWO/RFWU` interplay).
- `RFI s`: `s` outside 1..7 lifts as a single `unimplemented`. `RFI 1`
  reads `"eps1"`, which the architecture does not define, so the
  reference raises inside `il.reg` with nothing appended (`epc1` read is
  built but not appended). Ported as `Err(NoSuchRegister)`. The oracle
  records this encoding (`003110`) as return value `3` with empty IL, not
  `None`: the Python exception escapes the ctypes callback (BN only catches
  `OSError` there), the callback result is left unset and was observed as
  true, with `length` still at `len(data)`. Matching it needs a change in
  `lift::instruction_llil` (Err -> `Some(data.len())`), not here.
- `RSIL` reads `ps` twice (one `reg` for `at`, another for the new value)
  and builds `or(const(s), and(ps, 0xfffffff0))` with the constant on the
  left. `WAITI` writes the same PS value and models no wait.
- `RFME` sets `ps = meps` and returns through `mepc`; MESR.MEME is not
  cleared (reference TODO).

## MAC16

- `LDINC`/`LDDEC` (`_lift_mac_load`) write `"m" + str(r)`: `r` is the full
  4-bit field, so `r >= 4` names `m4`..`m15`, which do not exist; the
  reference raises at `set_reg` after building (but not appending) the
  load. Address update `a<s>` comes second.
- `_lift_mac_arithmetic` (all 64 `UMUL/MUL/MULA/MULS.{AA,AD,DA,DD}.{LL,HL,LH,HH}`
  forms and the 16 `MULA.{DA,DD}.*.{LDINC,LDDEC}` forms): `mac_right` for
  `AD`/`DD` is `m(2 + (t >> 2))`, so `t >= 8` names `m4`/`m5` and raises in
  `il.reg`. For the compound forms this happens *after* the
  `temp29 = [as +/- 4]` load has been appended, so the failed lift keeps
  that one instruction.
- The product is always 8 bytes (`mult.8` of two 8-byte extensions), the
  accumulator is `zx(acclo) | zx(acchi) << 32` and the result goes through
  `temp28`; `acchi` receives `low_part.1(temp28 >> 32)` (no sign extension
  of ACC bits 39..32). `UMUL` zero-extends, every other op sign-extends.
- `UMUL`/`MUL` overwrite ACC with the product (no accumulate).
- Compound forms commit `a<s>` before `m<r&3>` (`mac_destination`), and
  the destination comes from the loaded `temp29`.

## Synchronization, cache, TLB, debug

- `S32RI` emits the `acquire` intrinsic after the store (not a release),
  same as `L32AI`.
- `_lift_intrinsic_1param_1result` (LDCT, LICT, LICW, PDTLB, PITLB,
  RDTLB0/1, RITLB0/1) builds an unused `reg.4(at)` expression.
- `IITLB` uses the misspelled intrinsic `invalidate_instruciton_TLB_entry`
  (the architecture defines it under that name).
- Cache "imm8" forms use offset `imm8 << 2`; "imm4" forms (`DIWB`,
  `DIWBI`, `DHU`, `DIU`, `DPFL`, `IHU`, `IIU`, `IPFL`) use `imm4 << 4`.
- `S32C1I` builds `reg(at)` and `reg(scompare1)` before the address and
  passes them as `[va, at, scompare1]` to
  `store_32bit_compare_conditional` with output `at`.
- `BREAK`/`BREAK.N` share one lifter (`debug_break`, no operands).
