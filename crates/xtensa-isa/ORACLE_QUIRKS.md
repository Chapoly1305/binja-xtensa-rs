# Oracle quirks reproduced on purpose

`xtensa-isa` copies the reference Python decoder (`binja_xtensa/instruction.py`
and `disassembly.py`) bit for bit. The golden oracle checks this. The cases
below look wrong when compared with the Xtensa ISA manual or with objdump. Each
one is still reproduced exactly. Do not fix any of them without also
regenerating the oracle and bumping its version. Encodings are written as the
little-endian word in hex, the same form the shard keys use. For example,
`107062` means the bytes `62 70 10`.

## Decoding

1. **A reserved slot gives a 3-byte `ILL` with no format.** Some table
   entries are `None`: op0 = 14/15, many sub-table holes, and the MAC16
   op2 = 10..15 entries. They decode to `ILL` with `valid = false`,
   `len = 3` and `format = None`. The fields that were read before the
   lookup failed stay set. For example, `00000e` gives only `op0=14`, and
   `00100d` (an `ST3` hole) gives `op0,r`. This `ILL` has the same mnemonic as
   the real `ILL` (`000000`, CALLX, valid). The only difference is
   `format`.
2. **A short input can report a 3-byte length.** A 1- or 2-byte input whose
   first byte selects a reserved slot decodes without an `IndexError`. It
   reports `len = 3`, which is longer than the input. Examples: `short.tsv`
   key `0e` (1 byte) and `0e12` (2 bytes). Another example is `0d10`, an `ST3` hole
   (op0=13, r=1).
3. **CUST0/CUST1 are treated as reserved.** QRST op1 = 6/7 has no
   `_decode_CUST*` handler, so it falls back to item 1 with fields
   `op0,op1`. Example: `060000`.
4. **RER/WER decode through `ACCER`.** RST1 op2 = 7 with r = 6/7 decodes as
   `RER`/`WER`, as well as the ST1 encodings the manual gives (RST0 op2 = 4,
   r = 6/7). Example: `716000` → `RER`. The reference comment says this
   fixes a manual bug.
5. **MAC16 compound loads always use the `MULA` mnemonic.**
   `MULA.{DA,DD}.{half}.{LDINC,LDDEC}` is chosen by op2 only, for every op1.
   Encodings with op1 ∉ 8..11 are marked invalid but keep the `MULA` name.
   `mac_left` is `m<r >> 2` and `mac_destination` is `m<r & 3>`, even when
   r ≥ 8 (that encoding is invalid).
6. **MAC16 register names out of range.** For `DD`/`AD` forms, `mac_right`
   is `m<2 + (t >> 2)>`, which gives `m4`/`m5` when t ≥ 8. For
   `LDINC`/`LDDEC`, the disassembly prints `m<r>` with the full 4-bit r
   (`m4`..`m15` on invalid encodings). These registers do not exist.
7. **MAC16 `UMUL.{AD,DA,DD}.*` mnemonics exist but are never valid.** The
   arithmetic validity rule is `op1 >= 4 or kind == "AA"`. The mnemonic is
   still built from `op1 >> 2`.
8. **`simm6()` cannot be negative.** It is `sign_extend(imm6, 8)`, so a
   6-bit value never becomes negative. Nothing uses it: `BEQZ.N`/`BNEZ.N`
   use the unsigned `imm6`, which is correct.

## Disassembly

9. **Cache, loop and conditional-store immediates are printed raw.**
   - `DHI/DHWB/DHWBI/DII/DPFR/DPFRO/DPFW/DPFWO/IHI/III/IPF` print the raw
     imm8. The manual offset is `imm8 << 2`. Example: `107062` →
     `DHI a0, 16`, but the offset is 64.
   - `DHU/DIU/DIWB/DIWBI/DPFL/IHU/IIU/IPFL` print the raw imm4. The manual
     offset is `imm4 << 4`. Example: `307582` → `DPFL a5, 3`.
   - `S32C1I` prints the raw imm8 instead of `imm8 << 2`. Example: `10e002`.
   - `LOOP/LOOPNEZ/LOOPGTZ` print the raw imm8 as an integer token instead of
     the loop-end address. They are also missing from `_target_offset_map`,
     so `target_offset()` returns `None` for them. Example: `108076` →
     `LOOP a0, 16`.
10. **Token sizes are inconsistent.** Some `inline0` values become 1-byte
    integer tokens: `L32E`/`S32E` (negative offsets -64..-4), `SLLI`,
    `SRAI`, `SSAI`, `SEXT`, `BBCI`/`BBSI`, and both EXTUI operands. Similar
    offsets on other instructions become 4-byte tokens. The golden file
    records `size` as 1 for these.
11. **Unknown special and user registers are printed as decimal numbers.**
    Registers missing from `_special_reg_map` or `_user_reg_map` print as
    `RSR.<decimal>`. Examples: `030600` → `RSR.6`, `f30e80` → `WUR.14`. Many
    real LX6/LX7 special registers are missing, for example MEMCTL (97),
    CONFIGID0/1 (176/208) and PREFCTL (40).
12. **Register sizes in the special register table.** `MECR` is listed as
    3 bytes and `DEBUGCAUSE` as 2 bytes. `SPECIAL_REGS` exports these sizes
    unchanged.
13. **Address arithmetic does not wrap.** `target_offset`/`mem_offset` use
    Python integers, with no 32-bit wraparound. For a negative result,
    `hex(v)[2:]` prints the text `x…` without the minus sign, for example
    `x5` for -5. The port uses `i64` and copies this text. At the two oracle
    addresses (0x40080000, 0x400D1233) no result is negative or 32 bits or
    wider, so the golden data does not cover this case. Callers that pass
    addresses near 0 or 2^32 must mask the result themselves.
