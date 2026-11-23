# Workflow quirks

Reference behaviour reproduced on purpose in `src/workflow/` (ports of
`loop_workflow.py`, `window_tail_workflow.py`, `vector_profile.py`) and
`src/il_read.rs` (port of the Python API's `LowLevelILFunction.copy_expr_to`).

## Registration

- Workflow `matteroverwatch.xtensa.loops` is a clone of
  `core.function.metaAnalysis`; activities are registered in the order
  loopEnds, vectorProfile, sharedWindowTail, but inserted after
  `core.function.generateLiftedIL` in the order loopEnds, sharedWindowTail,
  vectorProfile (that is the execution order). Configuration JSON strings are
  the reference's `json.dumps` output byte for byte.
- Settings `arch.xtensa.windowVectorProfile` (default `generic`) and
  `arch.xtensa.depcPresence` (default `unknown`) are registered on the
  `default` settings instance, with the `arch` group re-registered, as
  importing `vector_profile` does.
- Workflow and settings are only registered when the architecture is
  registered as `xtensa` (not in the `XTENSA_RS_ARCH_NAME` side-by-side mode).
- If `insert_after` fails, the reference's `assert` aborts the import and the
  workflow is never registered; the port returns without registering.

## Exceptions

- `Activity._action` catches every Python exception and only logs it. A raise
  in a transform therefore leaves the lifted IL exactly as it was: the
  destination function being built is dropped, not installed. The port
  models every raise site as `Err(Abort)` at the same point (also a panic,
  which must not unwind into the core). The port does not log.
- The loop workflow calls the lifter's `lift()` directly (not the
  architecture callback), so a lifter raise during a re-lift aborts the whole
  transform, while a lift function returning `None` does not.
  `Raise::ReturnedNone` is therefore treated as success there.

## Loop workflow

- Instructions are decoded with `Instruction.decode` without the validity
  check the architecture callbacks apply; addresses whose 3-byte read does
  not decode (short read) are skipped.
- Dict order is observable: the dynamic loop-end `jump_to` label map lists
  every decoded instruction address in first-seen order (basic blocks in
  core order, then instruction index). The port keeps insertion-ordered maps.
- `endpoints[address]` keeps the last matching `(begin, end)` when several
  loops end at the same address.
- Every IL instruction whose address is an endpoint is dropped and the
  endpoint is re-lifted once, at its first occurrence, with the
  `_xtensa_conditional_handler` hook installed (ported as
  `Il::set_conditional_handler`, consulted first by `lift_cond`). That
  includes window-check IL tagged with the address, except the region of the
  shared overflow tail reached from the `0x100000000` label, which is copied.
- Branch endpoints (`mnem.startswith('B')`) get the loop check only through
  the conditional handler, on the fall-through path.
- `transfer(target)` with no label for the target emits
  `jump(const_pointer(4, target))`; a `None` branch target raises in ctypes
  and aborts the transform.

## Window tail workflow

- Sites are recognised by the core's text of the `temp24` source,
  `(windowbase + temp25.d) & 0xf`; the port compares the same core text
  (`BNGetLowLevelILExprText`), not a structural match.
- A site's block is cut after the site (`goto shared`); the rest of that
  block is not copied, even when it is not part of a discarded region.

## Vector profile

- Rewrites the lifted IL in place with `replace_expr` over a snapshot of
  `get_expr_count()`; every `LLIL_REG` expression slot is visited, including
  ones not reachable from an instruction. Finalizes only when something was
  replaced.

## copy_expr_to

- Copies drop IL attributes (e.g. `ILTransparentCopy`) and use the
  original expression's address and source operand (`...WithLocation`
  calls), except `CALL_PARAM` inside an intrinsic and the `const_pointer` of a
  `GOTO` without a label, which use the destination's current address.
- `IF` without a label for either target becomes `undefined`; `GOTO`
  without a label becomes `jump(const_pointer(4, target address))`;
  `JUMP_TO` with any target lacking a label becomes `jump(dest)`.
- Flag write types come back as 0 (the architecture defines none).
- Operations the Python method does not handle raise `NotImplementedError`
  and abort the transform; the port does the same. `ASSERT`, `FORCE_VER`
  and `FLAG_GROUP`, which Python copies through cached value sets and flag
  group names, are not ported and also abort. None of them occurs in Xtensa
  lifted IL (no flags, and assertions are only added to later IL forms).

## Whole-binary comparison notes (not a port difference)

- Binary Ninja lifts the `jump(const)` of `J` either as a plain `jump(c)` or
  as `jump_to(c, {c: i})`, depending on analysis order. The choice varies
  between runs of the same plugin with different worker counts (2 vs 16
  workers of the native plugin differ in 9 of 1,166 functions on an ESP32
  subset). LLIL instruction indices of the affected functions shift with it.
  `harness/fn_compare.py --normalize-jump-to` treats the two forms as equal;
  LLIL differences left in those same functions are index shifts.
