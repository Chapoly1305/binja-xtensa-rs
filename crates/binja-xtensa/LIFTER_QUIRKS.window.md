# Lifter quirks: window module

Reference behaviour reproduced on purpose in `src/lift/window.rs`
(`window_bank.py`, `window_exceptions.py`, `lifter.py` "Special register
instructions" through `_lift_QUOS`).

## window_check (runs before almost every instruction)

- The overflow handler body (bank rotation + vector jumps) is emitted only
  once per IL function, under a core label registered at the synthetic address
  `0x100000000`. The first instruction in a function that needs the check
  emits the full body; later ones emit `goto` to that label. So the same
  encoding lifts to different IL depending on what was lifted before it in the
  same function.
- `condition = and_expr(1, cmp_uge(4, ..), window_bit(..))`: a 1-byte AND of
  two comparison results.
- `maximum_group` is a single expression index reused in all three group
  comparisons (and in ENTRY it is `(ps >> 16) & 3`, built once and reused).
- The exception path sets `ps = ((ps & 0xfffff0ff) | (windowbase << 8)) | 16`
  (OWB from `windowbase`, EXCM set), `epc1 = address`, then rotates by
  `windowbase + temp25`. `temp25` is only assigned on the paths that reach
  the exception label, but in the shared-label reuse case the rotation reads
  the `temp25` of whichever instruction jumped there.
- If the core returns no label after `add_label_for_address`, the reference
  `assert` fails: `Err(Raise::Other(..))` after the appends so far.

## rotate_bank

- 2 x 16-way dispatch (`if windowbase == k`), each arm copying 16 registers:
  ~550 IL instructions per rotation. `temp24` holds the new window; the
  `windowbase` register is written between the two dispatches. Ends in a
  `nop` so the join label is materialized.
- `ar` index is `(window*4 + i) % 64`.
- `rotate_bank_compact` is ported but, as in the reference, unused.

## window_return (RETW, RETW.N)

- `temp20 = (a0 & 0x3fffffff) | (address & 0xc0000000)`, a non-wrapped
  `const(4, ..)` (not `const_pointer`).
- The "invalid" path is `trap(0)`; the normal return clears the WindowStart
  bit and returns to `temp20` without rotating the bank; only the underflow
  path rotates.

## Windowed calls (CALL4/8/12, CALLX4/8/12)

- Every register move is a `SET_REG` with the `ILTransparentCopy` attribute
  (0x1000) set via `set_expr_attributes` before `append`.
- After copying `a[i+n] -> a[i]`, `a1` is overwritten with `temp1` (the
  caller's `a1`), even for CALL12 where the callee's a1 would be a13.
- CALL0 uses `const` for the target; CALLn uses `const_pointer`.

## ENTRY

- Calls `window_check` itself (ENTRY is in `SPECIAL_WINDOW_RULES`, so the
  dispatcher does not), with group `(ps >> 16) & 3`.
- Sets `as = a1 - imm` *before* updating WindowBase/WindowStart, and the
  register bank is not rotated (only `windowbase`/`windowstart` change).

## MOVSP

- The exception path uses `general_exception.raise_exception(il, 5, addr)`;
  ported as a private copy in window.rs (general_exception.py is outside this
  module). The fall-through is `_lift_MOV_N` (`at = as`), also inlined.
- The `present` condition is `or_expr(1, or_expr(1, ..), ..)` over the three
  window bits.

## RSR / WSR / XSR / RUR / WUR

- Register name is the lower-cased `_special_reg_map`/`_user_reg_map` name, or
  `"sr<N>"`/`"ur<N>"` when absent. `sr72`/`sr73` resolve to
  `windowbase`/`windowstart` this way; numbers that are absent from the map
  and from the architecture register list raise (`Raise::NoSuchRegister`)
  before any append.
- Only `sr == 17` (ACCHI) is accessed with size 1 (`sign_extend(4, reg(1))` /
  `set_reg(1, low_part(1, ..))`). Other registers whose table size is not 4
  (SAR, EXCCAUSE, MECR, ...) are still read and written with size 4.
- RUR/WUR use the `sr` field as the user register number.
- XSR goes through `LLIL_TEMP(0)`.

## MULSH / MULUH

- `low_part(4, lsr(8, mul_dp(4, as, at), const(1, 32)))`: the double
  precision product is built with size 4 and shifted with size 8.
