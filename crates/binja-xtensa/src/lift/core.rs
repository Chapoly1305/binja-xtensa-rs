//! Port of the reference `lifter.py` core-architecture lift functions:
//! lines 146-773 ("Core Architecture Instructions" through `_lift_S32I_N`)
//! and lines 1275-1469 (`_lift_anyall` through `_lift_NSAU`: boolean,
//! miscellaneous-operations and NSA/NSAU instructions).
//!
//! Each function is a line-by-line port: sub-expressions are bound in the
//! order Python evaluates them (arguments left to right, innermost first),
//! and a Python exception becomes `Err(Raise::..)` after the same appends.
//! Oddities kept on purpose are listed in `LIFTER_QUIRKS.core.md`.

use xtensa_isa::Insn;

use super::common::{lift_cmov, lift_cond, rn, target, Handler};
use super::{Lift, Raise};
use crate::il::{Il, E, R};
use crate::regs;

/// A two-operand `il` builder method (`il.add`, `il.and_expr`, ...).
pub type BinOp = fn(&Il, usize, E, E) -> E;

#[inline]
fn done(insn: &Insn) -> Lift {
    Ok(insn.len as usize)
}

/// `insn.inline0(addr)`; the bound method exists for every opcode that
/// reaches a caller here.
#[inline]
fn inline0(insn: &Insn) -> Result<i64, Raise> {
    insn.inline0().ok_or(Raise::Other("insn.inline0 is missing"))
}

/// An optional attribute used in arithmetic (`None` raises `TypeError`).
#[inline]
fn some<T>(v: Option<T>, site: &'static str) -> Result<T, Raise> {
    v.ok_or(Raise::Other(site))
}

#[inline]
fn sar() -> Result<R, Raise> {
    regs::reg("sar")
}

// ------------------------------------------------------------------------
// Core architecture / code density option
// ------------------------------------------------------------------------

fn lift_abs(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let value = il.reg(4, rn(insn, "at")?);
    let c31 = il.const_(1, 31);
    let sign = il.arith_shift_right(4, value, c31);
    let x = il.xor_expr(4, value, sign);
    let result = il.sub(4, x, sign);
    il.append(il.set_reg(4, rn(insn, "ar")?, result));
    done(insn)
}

/// `ar = op(as, at)` (ADD, ADD.N, AND, OR, SUB, XOR).
fn rrr(insn: &Insn, il: &Il, op: BinOp) -> Lift {
    let ar = rn(insn, "ar")?;
    let a = il.reg(4, rn(insn, "as")?);
    let b = il.reg(4, rn(insn, "at")?);
    let v = op(il, 4, a, b);
    il.append(il.set_reg(4, ar, v));
    done(insn)
}

fn lift_add(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    rrr(insn, il, Il::add)
}
fn lift_add_n(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    rrr(insn, il, Il::add)
}
fn lift_and(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    rrr(insn, il, Il::and_expr)
}
fn lift_or(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    rrr(insn, il, Il::or_expr)
}
fn lift_sub(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    rrr(insn, il, Il::sub)
}
fn lift_xor(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    rrr(insn, il, Il::xor_expr)
}

fn lift_addi(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let at = rn(insn, "at")?;
    let a = il.reg(4, rn(insn, "as")?);
    let imm = some(insn.simm8(), "ADDI: sign_extend(None)")?;
    let c = il.const_(4, imm);
    let v = il.add(4, a, c);
    il.append(il.set_reg(4, at, v));
    done(insn)
}

fn lift_addi_n(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let ar = rn(insn, "ar")?;
    let a = il.reg(4, rn(insn, "as")?);
    let c = il.const_(4, inline0(insn)?);
    let v = il.add(4, a, c);
    il.append(il.set_reg(4, ar, v));
    done(insn)
}

/// `instruction.sign_extend`.
fn sign_extend(value: i64, bits: u32) -> i64 {
    let sign_bit = 1i64 << (bits - 1);
    (value & (sign_bit - 1)) - (value & sign_bit)
}

fn lift_addmi(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let imm8 = some(insn.imm8(), "ADDMI: sign_extend(None)")?;
    let constant = sign_extend(imm8 as i64, 8) << 8;
    let at = rn(insn, "at")?;
    let a = il.reg(4, rn(insn, "as")?);
    let c = il.const_(4, constant);
    let v = il.add(4, a, c);
    il.append(il.set_reg(4, at, v));
    done(insn)
}

/// `_lift_addx` / `_lift_subx`: `ar = op(as << x_bits, at)`.
fn lift_shifted(x_bits: i64, insn: &Insn, il: &Il, op: BinOp) -> Lift {
    let ar = rn(insn, "ar")?;
    let a = il.reg(4, rn(insn, "as")?);
    let c = il.const_(4, x_bits);
    let sh = il.shift_left(4, a, c);
    let b = il.reg(4, rn(insn, "at")?);
    let v = op(il, 4, sh, b);
    il.append(il.set_reg(4, ar, v));
    done(insn)
}

fn lift_addx2(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lift_shifted(1, insn, il, Il::add)
}
fn lift_addx4(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lift_shifted(2, insn, il, Il::add)
}
fn lift_addx8(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lift_shifted(3, insn, il, Il::add)
}
fn lift_subx2(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lift_shifted(1, insn, il, Il::sub)
}
fn lift_subx4(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lift_shifted(2, insn, il, Il::sub)
}
fn lift_subx8(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lift_shifted(3, insn, il, Il::sub)
}

// ---- branches ----------------------------------------------------------

/// BALL / BNALL: `cmp(at & ~as, 0)`.
fn branch_all(insn: &Insn, addr: u64, il: &Il, cmp: BinOp) -> Lift {
    let t = il.reg(4, rn(insn, "at")?);
    let s = il.reg(4, rn(insn, "as")?);
    let ns = il.not_expr(4, s);
    let a = il.and_expr(4, t, ns);
    let z = il.const_(4, 0);
    let cond = cmp(il, 4, a, z);
    lift_cond(cond, insn, addr, il)
}

/// BANY / BNONE: `cmp(as & at, 0)`.
fn branch_any(insn: &Insn, addr: u64, il: &Il, cmp: BinOp) -> Lift {
    let s = il.reg(4, rn(insn, "as")?);
    let t = il.reg(4, rn(insn, "at")?);
    let a = il.and_expr(4, s, t);
    let z = il.const_(4, 0);
    let cond = cmp(il, 4, a, z);
    lift_cond(cond, insn, addr, il)
}

fn lift_ball(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    branch_all(insn, addr, il, Il::compare_equal)
}
fn lift_bnall(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    branch_all(insn, addr, il, Il::compare_not_equal)
}
fn lift_bany(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    branch_any(insn, addr, il, Il::compare_not_equal)
}
fn lift_bnone(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    branch_any(insn, addr, il, Il::compare_equal)
}

fn lift_bbc(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let s = il.reg(4, rn(insn, "as")?);
    let t = il.reg(4, rn(insn, "at")?);
    let tb = il.test_bit(4, s, t);
    let z = il.const_(4, 0);
    let cond = il.compare_equal(4, tb, z);
    lift_cond(cond, insn, addr, il)
}

fn lift_bbci(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let s = il.reg(4, rn(insn, "as")?);
    let b = il.const_(4, inline0(insn)?);
    let tb = il.test_bit(4, s, b);
    let z = il.const_(4, 0);
    let cond = il.compare_equal(4, tb, z);
    lift_cond(cond, insn, addr, il)
}

fn lift_bbs(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let s = il.reg(4, rn(insn, "as")?);
    let t = il.reg(4, rn(insn, "at")?);
    let cond = il.test_bit(4, s, t);
    lift_cond(cond, insn, addr, il)
}

fn lift_bbsi(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let s = il.reg(4, rn(insn, "as")?);
    let b = il.const_(4, inline0(insn)?);
    let cond = il.test_bit(4, s, b);
    lift_cond(cond, insn, addr, il)
}

/// `cmp(as, at)` branches.
fn branch_rr(insn: &Insn, addr: u64, il: &Il, cmp: BinOp) -> Lift {
    let s = il.reg(4, rn(insn, "as")?);
    let t = il.reg(4, rn(insn, "at")?);
    let cond = cmp(il, 4, s, t);
    lift_cond(cond, insn, addr, il)
}

/// `cmp(as, imm)` branches; `imm` is evaluated after `as`.
fn branch_ri(insn: &Insn, addr: u64, il: &Il, cmp: BinOp, imm: fn(&Insn) -> Option<i64>) -> Lift {
    let s = il.reg(4, rn(insn, "as")?);
    let v = some(imm(insn), "b4const: KeyError")?;
    let c = il.const_(4, v);
    let cond = cmp(il, 4, s, c);
    lift_cond(cond, insn, addr, il)
}

fn zero(_: &Insn) -> Option<i64> {
    Some(0)
}

fn lift_beq(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    branch_rr(insn, addr, il, Il::compare_equal)
}
fn lift_bne(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    branch_rr(insn, addr, il, Il::compare_not_equal)
}
fn lift_bge(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    branch_rr(insn, addr, il, Il::compare_signed_greater_equal)
}
fn lift_bgeu(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    branch_rr(insn, addr, il, Il::compare_unsigned_greater_equal)
}
fn lift_blt(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    branch_rr(insn, addr, il, Il::compare_signed_less_than)
}
fn lift_bltu(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    branch_rr(insn, addr, il, Il::compare_unsigned_less_than)
}
fn lift_beqi(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    branch_ri(insn, addr, il, Il::compare_equal, Insn::b4const)
}
fn lift_bnei(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    branch_ri(insn, addr, il, Il::compare_not_equal, Insn::b4const)
}
fn lift_bgei(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    branch_ri(insn, addr, il, Il::compare_signed_greater_equal, Insn::b4const)
}
fn lift_blti(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    branch_ri(insn, addr, il, Il::compare_signed_less_than, Insn::b4const)
}
fn lift_bgeui(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    branch_ri(insn, addr, il, Il::compare_unsigned_greater_equal, Insn::b4constu)
}
fn lift_bltui(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    branch_ri(insn, addr, il, Il::compare_unsigned_less_than, Insn::b4constu)
}
fn lift_beqz(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    branch_ri(insn, addr, il, Il::compare_equal, zero)
}
fn lift_bnez(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    branch_ri(insn, addr, il, Il::compare_not_equal, zero)
}
fn lift_bgez(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    branch_ri(insn, addr, il, Il::compare_signed_greater_equal, zero)
}
fn lift_bltz(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    branch_ri(insn, addr, il, Il::compare_signed_less_than, zero)
}

// ---- intrinsics without operands --------------------------------------

fn no_operand_intrinsic(insn: &Insn, il: &Il, name: &str) -> Lift {
    let intr = regs::intrinsic(name)?;
    il.append(il.intrinsic(&[], intr, &[]));
    done(insn)
}

fn lift_dsync(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    no_operand_intrinsic(insn, il, "dsync")
}
fn lift_esync(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    no_operand_intrinsic(insn, il, "esync")
}
fn lift_isync(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    no_operand_intrinsic(insn, il, "isync")
}
fn lift_rsync(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    no_operand_intrinsic(insn, il, "rsync")
}
fn lift_extw(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    no_operand_intrinsic(insn, il, "extw")
}
fn lift_memw(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    no_operand_intrinsic(insn, il, "memw")
}

// ---- moves, shifts, misc ----------------------------------------------

fn lift_extui(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let inp = il.reg(4, rn(insn, "at")?);
    let bits = some(insn.inline1(), "EXTUI: insn.inline1 is missing")?;
    let mask = (1i64 << bits) - 1;
    let mask_il = il.const_(4, mask);
    // `if shiftimm:` -- None and 0 both take the no-shift path.
    let anded = match insn.extui_shiftimm() {
        Some(shiftimm) if shiftimm != 0 => {
            let shift_il = il.const_(1, shiftimm);
            let shifted = il.logical_shift_right(4, inp, shift_il);
            il.and_expr(4, shifted, mask_il)
        }
        _ => il.and_expr(4, inp, mask_il),
    };
    il.append(il.set_reg(4, rn(insn, "ar")?, anded));
    done(insn)
}

fn lift_j(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let c = il.const_(4, target(insn, addr)?);
    il.append(il.jump(c));
    done(insn)
}

fn lift_jx(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let s = il.reg(4, rn(insn, "as")?);
    il.append(il.jump(s));
    done(insn)
}

fn lift_mov_n(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let at = rn(insn, "at")?;
    let s = il.reg(4, rn(insn, "as")?);
    il.append(il.set_reg(4, at, s));
    done(insn)
}

/// MOVEQZ/MOVGEZ/MOVNEZ/MOVLTZ: `cmp(at, 0)` then `_lift_cmov`.
fn cmov_at_zero(insn: &Insn, il: &Il, cmp: BinOp) -> Lift {
    let t = il.reg(4, rn(insn, "at")?);
    let z = il.const_(4, 0);
    let cond = cmp(il, 4, t, z);
    lift_cmov(cond, insn, il, false)
}

fn lift_moveqz(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    cmov_at_zero(insn, il, Il::compare_equal)
}
fn lift_movgez(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    cmov_at_zero(insn, il, Il::compare_signed_greater_equal)
}
fn lift_movnez(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    cmov_at_zero(insn, il, Il::compare_not_equal)
}
fn lift_movltz(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    cmov_at_zero(insn, il, Il::compare_signed_less_than)
}

fn lift_movi(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let at = rn(insn, "at")?;
    let c = il.const_(4, inline0(insn)?);
    il.append(il.set_reg(4, at, c));
    done(insn)
}

fn lift_movi_n(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let as_ = rn(insn, "as")?;
    let c = il.const_(4, inline0(insn)?);
    il.append(il.set_reg(4, as_, c));
    done(insn)
}

fn lift_neg(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let ar = rn(insn, "ar")?;
    let t = il.reg(4, rn(insn, "at")?);
    let v = il.neg_expr(4, t);
    il.append(il.set_reg(4, ar, v));
    done(insn)
}

fn lift_nop(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    il.append(il.nop());
    done(insn)
}

fn lift_sll(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let ar = rn(insn, "ar")?;
    let s = il.reg(4, rn(insn, "as")?);
    let c32 = il.const_(1, 32);
    let sa = il.reg(1, sar()?);
    let amount = il.sub(1, c32, sa);
    let v = il.shift_left(4, s, amount);
    il.append(il.set_reg(4, ar, v));
    done(insn)
}

fn lift_slli(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let ar = rn(insn, "ar")?;
    let s = il.reg(4, rn(insn, "as")?);
    let c = il.const_(1, inline0(insn)?);
    let v = il.shift_left(4, s, c);
    il.append(il.set_reg(4, ar, v));
    done(insn)
}

fn lift_sra(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let ar = rn(insn, "ar")?;
    let t = il.reg(4, rn(insn, "at")?);
    let sa = il.reg(1, sar()?);
    let v = il.arith_shift_right(4, t, sa);
    il.append(il.set_reg(4, ar, v));
    done(insn)
}

fn lift_srai(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let ar = rn(insn, "ar")?;
    let t = il.reg(4, rn(insn, "at")?);
    let c = il.const_(4, inline0(insn)?);
    let v = il.arith_shift_right(4, t, c);
    il.append(il.set_reg(4, ar, v));
    done(insn)
}

fn lift_src(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let hi = rn(insn, "as")?;
    let lo = rn(insn, "at")?;
    let operand = il.reg_split(8, hi, lo);
    let ar = rn(insn, "ar")?;
    let sa = il.reg(1, sar()?);
    let sh = il.logical_shift_right(8, operand, sa);
    let v = il.low_part(4, sh);
    il.append(il.set_reg(4, ar, v));
    done(insn)
}

fn lift_srl(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let ar = rn(insn, "ar")?;
    let t = il.reg(4, rn(insn, "at")?);
    let sa = il.reg(1, sar()?);
    let v = il.logical_shift_right(4, t, sa);
    il.append(il.set_reg(4, ar, v));
    done(insn)
}

fn lift_srli(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let ar = rn(insn, "ar")?;
    let t = il.reg(4, rn(insn, "at")?);
    let s = some(insn.s(), "SRLI: insn.s is None")?;
    let c = il.const_(4, s as i64);
    let v = il.logical_shift_right(4, t, c);
    il.append(il.set_reg(4, ar, v));
    done(insn)
}

/// `low_part(1, as) & 3`, shared by SSA8L and SSA8B.
fn as_low2(insn: &Insn, il: &Il) -> Result<E, Raise> {
    let s = il.reg(4, rn(insn, "as")?);
    let lp = il.low_part(1, s);
    let c3 = il.const_(1, 3);
    Ok(il.and_expr(1, lp, c3))
}

fn lift_ssa8l(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let low = as_low2(insn, il)?;
    let c3 = il.const_(1, 3);
    let result = il.shift_left(1, low, c3);
    il.append(il.set_reg(1, sar()?, result));
    done(insn)
}

fn lift_ssa8b(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let low = as_low2(insn, il)?;
    let c32 = il.const_(1, 32);
    let c3 = il.const_(1, 3);
    let sh = il.shift_left(1, low, c3);
    let result = il.sub(1, c32, sh);
    il.append(il.set_reg(1, sar()?, result));
    done(insn)
}

fn lift_ssai(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let c = il.const_(1, inline0(insn)?);
    il.append(il.set_reg(1, sar()?, c));
    done(insn)
}

/// `low_part(1, as) & 31`.
fn as_low5(insn: &Insn, il: &Il) -> Result<E, Raise> {
    let s = il.reg(4, rn(insn, "as")?);
    let lp = il.low_part(1, s);
    let c31 = il.const_(1, 31);
    Ok(il.and_expr(1, lp, c31))
}

fn lift_ssl(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let c32 = il.const_(1, 32);
    let m = as_low5(insn, il)?;
    let v = il.sub(1, c32, m);
    il.append(il.set_reg(1, sar()?, v));
    done(insn)
}

fn lift_ssr(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let m = as_low5(insn, il)?;
    il.append(il.set_reg(1, sar()?, m));
    done(insn)
}

// ---- loads and stores --------------------------------------------------

/// `as + imm`.
fn va(insn: &Insn, il: &Il, imm: i64) -> Result<E, Raise> {
    let s = il.reg(4, rn(insn, "as")?);
    let c = il.const_(4, imm);
    Ok(il.add(4, s, c))
}

fn lift_l8ui(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let imm8 = some(insn.imm8(), "L8UI: imm8 is None")?;
    let va = va(insn, il, imm8 as i64)?;
    let at = rn(insn, "at")?;
    let ld = il.load(1, va);
    let v = il.zero_extend(4, ld);
    il.append(il.set_reg(4, at, v));
    done(insn)
}

fn lift_l16si(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let va = va(insn, il, inline0(insn)?)?;
    let at = rn(insn, "at")?;
    let ld = il.load(2, va);
    let v = il.sign_extend(4, ld);
    il.append(il.set_reg(4, at, v));
    done(insn)
}

fn lift_l16ui(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let va = va(insn, il, inline0(insn)?)?;
    let at = rn(insn, "at")?;
    let ld = il.load(2, va);
    let v = il.zero_extend(4, ld);
    il.append(il.set_reg(4, at, v));
    done(insn)
}

/// L32I and L32I.N (identical IL).
fn lift_l32i(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let va = va(insn, il, inline0(insn)?)?;
    let at = rn(insn, "at")?;
    let ld = il.load(4, va);
    il.append(il.set_reg(4, at, ld));
    done(insn)
}

fn lift_l32r(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let off = some(insn.mem_offset(addr as u32), "L32R: mem_offset is None")?;
    let va = il.const_(4, off);
    let at = rn(insn, "at")?;
    let ld = il.load(4, va);
    il.append(il.set_reg(4, at, ld));
    done(insn)
}

fn lift_s8i(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let imm8 = some(insn.imm8(), "S8I: imm8 is None")?;
    let va = va(insn, il, imm8 as i64)?;
    let t = il.reg(4, rn(insn, "at")?);
    let v = il.low_part(1, t);
    il.append(il.store(1, va, v));
    done(insn)
}

fn lift_s16i(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let va = va(insn, il, inline0(insn)?)?;
    let t = il.reg(4, rn(insn, "at")?);
    let v = il.low_part(2, t);
    il.append(il.store(2, va, v));
    done(insn)
}

fn lift_s32i(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let va = va(insn, il, inline0(insn)?)?;
    let t = il.reg(4, rn(insn, "at")?);
    il.append(il.store(4, va, t));
    done(insn)
}

fn lift_s32i_n(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let va = va(insn, il, inline0(insn)?)?;
    // `"a" + str(insn.t)`: None gives "aNone", which get_reg_index rejects.
    let t = match insn.t() {
        Some(t) => regs::numbered("a", t as i64)?,
        None => return Err(Raise::NoSuchRegister),
    };
    let t = il.reg(4, t);
    il.append(il.store(4, va, t));
    done(insn)
}

// ------------------------------------------------------------------------
// Boolean option
// ------------------------------------------------------------------------

/// `_lift_anyall` (ALL4, ALL8, ANY4, ANY8).
fn lift_anyall(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let op = insn.mnemonic();
    let s_reg = il.reg(1, rn(insn, "bs")?);
    let offset = (op.as_bytes()[op.len() - 1] - b'0') as i64;
    let s = some(insn.s(), "anyall: s is None")? as i64;
    let kind = &op[..op.len() - 1];
    let mut temp = s_reg;
    for idx in (s + 1)..(s + offset).min(16) {
        match kind {
            "ALL" => {
                let b = il.reg(1, regs::numbered("b", idx)?);
                temp = il.and_expr(1, temp, b);
            }
            "ANY" => {
                let b = il.reg(1, regs::numbered("b", idx)?);
                temp = il.or_expr(1, temp, b);
            }
            _ => {}
        }
    }
    il.append(il.set_reg(2, rn(insn, "bt")?, temp));
    done(insn)
}

#[derive(Clone, Copy)]
enum BoolOp {
    Andb,
    Andbc,
    Orb,
    Orbc,
    Xorb,
}

/// `_lift_binop_B`.
fn lift_binop_b(insn: &Insn, il: &Il, op: BoolOp) -> Lift {
    let t = il.reg(1, rn(insn, "bt")?);
    let s = il.reg(1, rn(insn, "bs")?);
    let bit_t_neg = il.not_expr(1, t);
    let temp = match op {
        BoolOp::Andb => il.and_expr(1, s, t),
        BoolOp::Andbc => il.and_expr(1, s, bit_t_neg),
        BoolOp::Orb => il.or_expr(1, s, t),
        BoolOp::Orbc => il.or_expr(1, s, bit_t_neg),
        BoolOp::Xorb => il.xor_expr(1, s, t),
    };
    il.append(il.set_reg(1, rn(insn, "br")?, temp));
    done(insn)
}

fn lift_andb(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lift_binop_b(insn, il, BoolOp::Andb)
}
fn lift_andbc(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lift_binop_b(insn, il, BoolOp::Andbc)
}
fn lift_orb(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lift_binop_b(insn, il, BoolOp::Orb)
}
fn lift_orbc(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lift_binop_b(insn, il, BoolOp::Orbc)
}
fn lift_xorb(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lift_binop_b(insn, il, BoolOp::Xorb)
}

/// `_lift_BFT` (BF, BT).
fn lift_bft(insn: &Insn, addr: u64, il: &Il, bit: i64) -> Lift {
    let s = il.reg(1, rn(insn, "bs")?);
    let b = il.const_(1, bit);
    let cond = il.compare_equal(1, s, b);
    let true_label = il.new_label();
    let false_label = il.new_label();
    il.append(il.if_expr(cond, true_label, false_label));
    il.mark_label(true_label);
    let c = il.const_(4, target(insn, addr)?);
    il.append(il.jump(c));
    il.mark_label(false_label);
    done(insn)
}

fn lift_bf(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lift_bft(insn, addr, il, 0)
}
fn lift_bt(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lift_bft(insn, addr, il, 1)
}

/// `_lift_MOVFT(insn, addr, il, bit, float)`; the floating-point
/// `MOVF.S`/`MOVT.S` lambdas call it with `float = true`.
pub fn lift_movft(insn: &Insn, il: &Il, bit: i64, float: bool) -> Lift {
    let t = il.reg(1, rn(insn, "bt")?);
    let b = il.const_(1, bit);
    let cond = il.compare_equal(1, t, b);
    lift_cmov(cond, insn, il, float)
}

fn lift_movf(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lift_movft(insn, il, 0, false)
}
fn lift_movt(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lift_movft(insn, il, 1, false)
}

// ------------------------------------------------------------------------
// Miscellaneous operations option
// ------------------------------------------------------------------------

/// `_lift_minmax(cond_func, left, right, insn, addr, il)`.
pub fn lift_minmax(cond_func: BinOp, left: E, right: E, insn: &Insn, il: &Il) -> Lift {
    let true_label = il.new_label();
    let false_label = il.new_label();
    let end_label = il.new_label();
    let cond = cond_func(il, 4, left, right);
    il.append(il.if_expr(cond, true_label, false_label));

    il.mark_label(true_label);
    il.append(il.set_reg(4, rn(insn, "ar")?, left));
    il.append(il.goto(end_label));

    il.mark_label(false_label);
    il.append(il.set_reg(4, rn(insn, "ar")?, right));
    il.append(il.goto(end_label));
    il.mark_label(end_label);
    done(insn)
}

fn minmax_as_at(insn: &Insn, il: &Il, cmp: BinOp) -> Lift {
    let left = il.reg(4, rn(insn, "as")?);
    let right = il.reg(4, rn(insn, "at")?);
    lift_minmax(cmp, left, right, insn, il)
}

fn lift_maxu(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    minmax_as_at(insn, il, Il::compare_unsigned_greater_equal)
}
fn lift_max(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    minmax_as_at(insn, il, Il::compare_signed_greater_equal)
}
fn lift_min(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    minmax_as_at(insn, il, Il::compare_signed_less_equal)
}
fn lift_minu(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    minmax_as_at(insn, il, Il::compare_unsigned_less_equal)
}

/// SALT / SALTU: `ar = zx(cmp(as, at))`.
fn set_less(insn: &Insn, il: &Il, cmp: BinOp) -> Lift {
    let s = il.reg(4, rn(insn, "as")?);
    let t = il.reg(4, rn(insn, "at")?);
    let value = cmp(il, 4, s, t);
    let ar = rn(insn, "ar")?;
    let v = il.zero_extend(4, value);
    il.append(il.set_reg(4, ar, v));
    done(insn)
}

fn lift_salt(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    set_less(insn, il, Il::compare_signed_less_than)
}
fn lift_saltu(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    set_less(insn, il, Il::compare_unsigned_less_than)
}

fn lift_clamps(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let x = il.reg(4, rn(insn, "as")?);
    let ar_reg = il.reg(4, rn(insn, "ar")?);
    let t = some(insn.t(), "CLAMPS: t is None")? as u32;
    let imm1 = il.const_(4, -(1i64 << (t + 7)));
    let imm2 = il.const_(4, (1i64 << (t + 7)) - 1);
    // Quirk: `ar_reg` is the *expression index* of `il.reg(4, ar)`, and
    // `get_reg_index` passes an int through as a register index.
    let dest = R(ar_reg as u32);

    let underflow_label = il.new_label();
    let overflow_label = il.new_label();
    let value_label = il.new_label();
    let false_label = il.new_label();
    let end_label = il.new_label();

    let cond = il.compare_signed_less_equal(4, x, imm1);
    il.append(il.if_expr(cond, underflow_label, false_label));

    il.mark_label(underflow_label);
    il.append(il.set_reg(4, dest, imm1));
    il.append(il.goto(end_label));

    il.mark_label(false_label);
    let cond = il.compare_signed_greater_equal(4, x, imm2);
    il.append(il.if_expr(cond, overflow_label, value_label));

    il.mark_label(overflow_label);
    il.append(il.set_reg(4, dest, imm2));
    il.append(il.goto(end_label));

    il.mark_label(value_label);
    il.append(il.set_reg(4, dest, x));
    il.append(il.goto(end_label));

    il.mark_label(end_label);
    done(insn)
}

fn lift_sext(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let reg_as = il.reg(4, rn(insn, "as")?);
    let _reg_ar = il.reg(4, rn(insn, "ar")?);
    let b = inline0(insn)?;
    let c1 = il.const_(4, 31 - b);
    let left_shifted = il.shift_left(4, reg_as, c1);
    let c2 = il.const_(4, 31 - b);
    let result = il.arith_shift_right(4, left_shifted, c2);
    il.append(il.set_reg(4, rn(insn, "at")?, result));
    done(insn)
}

fn lift_nsa(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let at = rn(insn, "at")?;
    let s = il.reg(4, rn(insn, "as")?);
    let v = il.count_leading_signs(4, s);
    il.append(il.set_reg(4, at, v));
    done(insn)
}

fn lift_nsau(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let at = rn(insn, "at")?;
    let s = il.reg(4, rn(insn, "as")?);
    let v = il.count_leading_zeros(4, s);
    il.append(il.set_reg(4, at, v));
    done(insn)
}

/// Python handler names (mnemonic with '.' replaced by '_') ported here.
pub fn handler(name: &str) -> Option<Handler> {
    Some(match name {
        "ABS" => lift_abs,
        "ADD" => lift_add,
        "ADD_N" => lift_add_n,
        "ADDI" => lift_addi,
        "ADDI_N" => lift_addi_n,
        "ADDMI" => lift_addmi,
        "ADDX2" => lift_addx2,
        "ADDX4" => lift_addx4,
        "ADDX8" => lift_addx8,
        "AND" => lift_and,
        "BALL" => lift_ball,
        "BANY" => lift_bany,
        "BBC" => lift_bbc,
        "BBCI" | "BBCI_L" => lift_bbci,
        "BBS" => lift_bbs,
        "BBSI" | "BBSI_L" => lift_bbsi,
        "BEQ" => lift_beq,
        "BEQI" => lift_beqi,
        "BEQZ" | "BEQZ_N" => lift_beqz,
        "BGE" => lift_bge,
        "BGEI" => lift_bgei,
        "BGEU" => lift_bgeu,
        "BGEUI" => lift_bgeui,
        "BGEZ" => lift_bgez,
        "BLT" => lift_blt,
        "BLTI" => lift_blti,
        "BLTU" => lift_bltu,
        "BLTUI" => lift_bltui,
        "BLTZ" => lift_bltz,
        "BNALL" => lift_bnall,
        "BNE" => lift_bne,
        "BNEI" => lift_bnei,
        "BNEZ" | "BNEZ_N" => lift_bnez,
        "BNONE" => lift_bnone,
        "DSYNC" => lift_dsync,
        "ESYNC" => lift_esync,
        "ISYNC" => lift_isync,
        "RSYNC" => lift_rsync,
        "EXTUI" => lift_extui,
        "EXTW" => lift_extw,
        "J" => lift_j,
        "JX" => lift_jx,
        "MEMW" => lift_memw,
        "MOV_N" => lift_mov_n,
        "MOVEQZ" => lift_moveqz,
        "MOVGEZ" => lift_movgez,
        "MOVNEZ" => lift_movnez,
        "MOVLTZ" => lift_movltz,
        "MOVI" => lift_movi,
        "MOVI_N" => lift_movi_n,
        "NEG" => lift_neg,
        "NOP" | "NOP_N" => lift_nop,
        "OR" => lift_or,
        "SLL" => lift_sll,
        "SLLI" => lift_slli,
        "SRA" => lift_sra,
        "SRAI" => lift_srai,
        "SRC" => lift_src,
        "SRL" => lift_srl,
        "SRLI" => lift_srli,
        "SSA8L" => lift_ssa8l,
        "SSA8B" => lift_ssa8b,
        "SSAI" => lift_ssai,
        "SSL" => lift_ssl,
        "SSR" => lift_ssr,
        "SUB" => lift_sub,
        "SUBX2" => lift_subx2,
        "SUBX4" => lift_subx4,
        "SUBX8" => lift_subx8,
        "XOR" => lift_xor,
        "L8UI" => lift_l8ui,
        "L16SI" => lift_l16si,
        "L16UI" => lift_l16ui,
        "L32I" | "L32I_N" => lift_l32i,
        "L32R" => lift_l32r,
        "S8I" => lift_s8i,
        "S16I" => lift_s16i,
        "S32I" => lift_s32i,
        "S32I_N" => lift_s32i_n,
        "ALL4" | "ALL8" | "ANY4" | "ANY8" => lift_anyall,
        "ANDB" => lift_andb,
        "ANDBC" => lift_andbc,
        "ORB" => lift_orb,
        "ORBC" => lift_orbc,
        "XORB" => lift_xorb,
        "BF" => lift_bf,
        "BT" => lift_bt,
        "MOVF" => lift_movf,
        "MOVT" => lift_movt,
        "SALT" => lift_salt,
        "SALTU" => lift_saltu,
        "MAXU" => lift_maxu,
        "MAX" => lift_max,
        "MIN" => lift_min,
        "MINU" => lift_minu,
        "CLAMPS" => lift_clamps,
        "SEXT" => lift_sext,
        "NSA" => lift_nsa,
        "NSAU" => lift_nsau,
        _ => return None,
    })
}
