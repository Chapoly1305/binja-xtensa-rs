//! Port of the reference lifter's Floating-point Coprocessor Option section
//! (`lifter.py` `_lift_ABS_S` .. `_lift_SSX`), the loop / exception /
//! interrupt / MAC16 / synchronization / cache / TLB / debug section
//! (`_lift_LOOP_simple` .. `_lift_mac_arithmetic`), and
//! `general_exception.py`.
//!
//! Each Python `il.f(..)` call is bound to a local in Python's evaluation
//! order (arguments left to right, innermost first). Register names are
//! resolved with `?` right before the builder call that resolves them in
//! Python, so a raise lands after the same appends.

pub mod general_exception;

use xtensa_isa::{Field, Insn, MacOperation, MacReg};

use super::common::{lift_cmov, rn, Handler};
use super::{Lift, Raise};
use crate::il::{temp, Il, E, R};
use crate::regs::{self, reg};

use general_exception::{double_return, raise_exception};

type BinOp = fn(&Il, usize, E, E) -> E;
type UnOp = fn(&Il, usize, E) -> E;

/// `getattr(insn, field)` where the reference uses the value in arithmetic
/// (`None` there raises `TypeError`).
fn fv(insn: &Insn, f: Field) -> Result<i64, Raise> {
    insn.field(f).map(|v| v as i64).ok_or(Raise::Other("field is None"))
}

/// `insn.inline0(addr)`; a missing bound method raises `AttributeError`.
fn inline0(insn: &Insn) -> Result<i64, Raise> {
    insn.inline0().ok_or(Raise::Other("insn.inline0 missing"))
}

fn len(insn: &Insn) -> Lift {
    Ok(insn.len as usize)
}

/// `il.float_const_single(2.0 ** exp)` (also `2 ** t` with an int, which
/// packs to the same single).
fn pow2_const(il: &Il, exp: i64) -> E {
    il.float_const_single(2f64.powi(exp as i32) as f32)
}

/// Python names (mnemonic with '.' replaced by '_') ported here.
pub fn handler(name: &str) -> Option<Handler> {
    Some(match name {
        // Floating-point Coprocessor Option
        "ABS_S" => lift_abs_s,
        "ADD_S" => lift_add_s,
        "MUL_S" => lift_mul_s,
        "NEG_S" => lift_neg_s,
        "SUB_S" => lift_sub_s,
        "MADD_S" => lift_madd_s,
        "MSUB_S" => lift_msub_s,
        "CEIL_S" => lift_ceil_s,
        "FLOAT_S" => lift_float_s,
        "UFLOAT_S" => lift_ufloat_s,
        "FLOOR_S" => lift_floor_s,
        "TRUNC_S" => lift_trunc_s_signed,
        "UTRUNC_S" => lift_utrunc_s,
        "ROUND_S" => lift_round_s,
        "MOVEQZ_S" => lift_moveqz_s,
        "MOVNEZ_S" => lift_movnez_s,
        "MOVGEZ_S" => lift_movgez_s,
        "MOVLTZ_S" => lift_movltz_s,
        "MOVF_S" => lift_movf_s,
        "MOVT_S" => lift_movt_s,
        "MOV_S" => lift_mov_s,
        "RFR" => lift_rfr,
        "WFR" => lift_wfr,
        "OEQ_S" => lift_oeq_s,
        "OLE_S" => lift_ole_s,
        "OLT_S" => lift_olt_s,
        "UEQ_S" => lift_ueq_s,
        "ULE_S" => lift_ule_s,
        "ULT_S" => lift_ult_s,
        "UN_S" => lift_un_s,
        "LSIU" => lift_lsiu,
        "LSXU" => lift_lsxu,
        "SSIU" => lift_ssiu,
        "SSXU" => lift_ssxu,
        "LSI" => lift_lsi,
        "LSX" => lift_lsx,
        "SSI" => lift_ssi,
        "SSX" => lift_ssx,
        // Loop Option
        "LOOP" => lift_loop,
        "LOOPNEZ" => lift_loopnez,
        "LOOPGTZ" => lift_loopgtz,
        // Exception Option
        "ILL" | "ILL_N" => lift_ill,
        "SYSCALL" => lift_syscall,
        "EXCW" => lift_excw,
        "RFE" => lift_rfe,
        "RFUE" => lift_rfue,
        "RFDE" => lift_rfde,
        // Interrupt Options
        "RFI" => lift_rfi,
        "RSIL" => lift_rsil,
        "WAITI" => lift_waiti,
        // Memory ECC/Parity Option
        "RFME" => lift_rfme,
        // MAC16 loads
        "LDINC" => lift_ldinc,
        "LDDEC" => lift_lddec,
        // Multiprocessor Synchronization Option
        "L32AI" => lift_l32ai,
        "S32RI" => lift_s32ri,
        // Conditional Store Option
        "S32C1I" => lift_s32c1i,
        // Debug Option
        "BREAK" | "BREAK_N" => lift_break,
        "RFDD" => lift_rfdd,
        "RFDO" => lift_rfdo,
        // Cache / TLB intrinsic lambdas
        "DHI" => lift_dhi,
        "DHWB" => lift_dhwb,
        "DHWBI" => lift_dhwbi,
        "DPFR" => lift_dpfr,
        "DPFRO" => lift_dpfro,
        "DPFW" => lift_dpfw,
        "DPFWO" => lift_dpfwo,
        "DII" => lift_dii,
        "DIWB" => lift_diwb,
        "DIWBI" => lift_diwbi,
        "DHU" => lift_dhu,
        "DIU" => lift_diu,
        "DPFL" => lift_dpfl,
        "LDCT" => lift_ldct,
        "SDCT" => lift_sdct,
        "IHI" => lift_ihi,
        "III" => lift_iii,
        "IPF" => lift_ipf,
        "IHU" => lift_ihu,
        "IIU" => lift_iiu,
        "IPFL" => lift_ipfl,
        "LICT" => lift_lict,
        "LICW" => lift_licw,
        "SICT" => lift_sict,
        "SICW" => lift_sicw,
        "IDTLB" => lift_idtlb,
        "IITLB" => lift_iitlb,
        "PDTLB" => lift_pdtlb,
        "PITLB" => lift_pitlb,
        "RDTLB0" => lift_rdtlb0,
        "RDTLB1" => lift_rdtlb1,
        "RITLB0" => lift_ritlb0,
        "RITLB1" => lift_ritlb1,
        "WDTLB" => lift_wdtlb,
        "WITLB" => lift_witlb,
        _ => return None,
    })
}

// ------------------------------------------------ binary/unary arithmetic ---

/// `set_reg(fr, op(4, reg fs))`.
fn fr_unary(insn: &Insn, il: &Il, op: UnOp) -> Lift {
    let s = il.reg(4, rn(insn, "fs")?);
    let v = op(il, 4, s);
    il.append(il.set_reg(4, rn(insn, "fr")?, v));
    len(insn)
}

fn lift_abs_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    fr_unary(insn, il, Il::float_abs)
}
fn lift_neg_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    fr_unary(insn, il, Il::float_neg)
}

/// `set_reg(fr, op(4, reg fs, reg ft))`.
fn fr_fs_ft(insn: &Insn, il: &Il, op: BinOp) -> Lift {
    let s = il.reg(4, rn(insn, "fs")?);
    let t = il.reg(4, rn(insn, "ft")?);
    let v = op(il, 4, s, t);
    il.append(il.set_reg(4, rn(insn, "fr")?, v));
    len(insn)
}

fn lift_add_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    fr_fs_ft(insn, il, Il::float_add)
}
fn lift_mul_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    fr_fs_ft(insn, il, Il::float_mult)
}
fn lift_sub_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    fr_fs_ft(insn, il, Il::float_sub)
}

/// `set_reg(fr, op(4, reg fr, float_mult(4, reg fs, reg ft)))`.
fn fused(insn: &Insn, il: &Il, op: BinOp) -> Lift {
    let r = il.reg(4, rn(insn, "fr")?);
    let s = il.reg(4, rn(insn, "fs")?);
    let t = il.reg(4, rn(insn, "ft")?);
    let m = il.float_mult(4, s, t);
    let v = op(il, 4, r, m);
    il.append(il.set_reg(4, rn(insn, "fr")?, v));
    len(insn)
}

fn lift_madd_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    fused(insn, il, Il::float_add)
}
fn lift_msub_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    fused(insn, il, Il::float_sub)
}

// --------------------------------------------- float to int rounding ---

/// `set_reg(ar, op(4, float_mult(4, reg fs, float_const_single(2**t))))`.
fn round_op(insn: &Insn, il: &Il, op: UnOp) -> Lift {
    let s = il.reg(4, rn(insn, "fs")?);
    let c = pow2_const(il, fv(insn, Field::T)?);
    let m = il.float_mult(4, s, c);
    let v = op(il, 4, m);
    il.append(il.set_reg(4, rn(insn, "ar")?, v));
    len(insn)
}

fn lift_ceil_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    round_op(insn, il, Il::ceil)
}
fn lift_floor_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    round_op(insn, il, Il::floor)
}
fn lift_round_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    round_op(insn, il, Il::round_to_int)
}

/// `FLOAT.S` (`zext = false`) and `UFLOAT.S` (`zext = true`).
fn int_to_float_scaled(insn: &Insn, il: &Il, zext: bool) -> Lift {
    let mut value = il.reg(4, rn(insn, "as")?);
    if zext {
        value = il.zero_extend(8, value);
    }
    let f = il.int_to_float(4, value);
    let c = pow2_const(il, -fv(insn, Field::T)?);
    let v = il.float_mult(4, f, c);
    il.append(il.set_reg(4, rn(insn, "fr")?, v));
    len(insn)
}

fn lift_float_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    int_to_float_scaled(insn, il, false)
}
fn lift_ufloat_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    int_to_float_scaled(insn, il, true)
}

/// `_lift_trunc_s(insn, addr, il, unsigned)`.
fn trunc_s(insn: &Insn, il: &Il, unsigned: bool) -> Lift {
    let value = il.reg(4, temp(30));
    let s = il.reg(4, rn(insn, "fs")?);
    let c = pow2_const(il, fv(insn, Field::T)?);
    let m = il.float_mult(4, s, c);
    il.append(il.set_reg(4, temp(30), m));
    let upper = il.new_label();
    let lower_check = il.new_label();
    let lower = il.new_label();
    let convert = il.new_label();
    let done = il.new_label();
    let maximum: i64 = if unsigned { 0xffff_ffff } else { 0x7fff_ffff };
    let threshold: f32 = if unsigned { 4_294_967_296.0 } else { 2_147_483_648.0 };
    let uo = il.float_compare_unordered(4, value, value);
    let th = il.float_const_single(threshold);
    let ge = il.float_compare_greater_equal(4, value, th);
    let invalid_high = il.or_expr(1, uo, ge);
    il.append(il.if_expr(invalid_high, upper, lower_check));
    il.mark_label(upper);
    let mx = il.const_(4, maximum);
    il.append(il.set_reg(4, rn(insn, "ar")?, mx));
    il.append(il.goto(done));
    il.mark_label(lower_check);
    let lo = il.float_const_single(-2_147_483_648.0);
    let le = il.float_compare_less_equal(4, value, lo);
    il.append(il.if_expr(le, lower, convert));
    il.mark_label(lower);
    let mn = il.const_(4, 0x8000_0000);
    il.append(il.set_reg(4, rn(insn, "ar")?, mn));
    il.append(il.goto(done));
    il.mark_label(convert);
    let tr = il.float_trunc(8, value);
    let lp = il.low_part(4, tr);
    il.append(il.set_reg(4, rn(insn, "ar")?, lp));
    il.mark_label(done);
    il.append(il.nop());
    len(insn)
}

fn lift_trunc_s_signed(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    trunc_s(insn, il, false)
}
fn lift_utrunc_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    trunc_s(insn, il, true)
}

// ------------------------------------------------------------- moves ---

/// `_lift_MOV_COND_S(insn, addr, il, comp)`.
fn mov_cond_s(insn: &Insn, il: &Il, comp: BinOp) -> Lift {
    let t = il.reg(4, rn(insn, "at")?);
    let z = il.const_(4, 0);
    let cond = comp(il, 4, t, z);
    lift_cmov(cond, insn, il, true)
}

fn lift_moveqz_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    mov_cond_s(insn, il, Il::compare_equal)
}
fn lift_movnez_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    mov_cond_s(insn, il, Il::compare_not_equal)
}
fn lift_movgez_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    mov_cond_s(insn, il, Il::compare_signed_greater_equal)
}
fn lift_movltz_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    mov_cond_s(insn, il, Il::compare_signed_less_than)
}

/// MOVF.S/MOVT.S use `_lift_MOVFT` from the Boolean Option section.
use super::core::lift_movft as movft;

fn lift_movf_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    movft(insn, il, 0, true)
}
fn lift_movt_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    movft(insn, il, 1, true)
}

/// `set_reg(4, dst, reg(4, src))`.
fn mov(insn: &Insn, il: &Il, dst: &str, src: &str) -> Lift {
    let s = il.reg(4, rn(insn, src)?);
    il.append(il.set_reg(4, rn(insn, dst)?, s));
    len(insn)
}

fn lift_mov_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    mov(insn, il, "fr", "fs")
}
fn lift_rfr(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    mov(insn, il, "ar", "fs")
}
fn lift_wfr(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    mov(insn, il, "fr", "as")
}

// ---------------------------------------------------- float compares ---

/// `_lift_float_compares(insn, addr, il, order, cond, merge)`.
fn float_compares(insn: &Insn, il: &Il, order: BinOp, cond: BinOp, merge: BinOp) -> Lift {
    let s = il.reg(4, rn(insn, "fs")?);
    let t = il.reg(4, rn(insn, "ft")?);
    let cond1 = order(il, 4, s, t);
    let s = il.reg(4, rn(insn, "fs")?);
    let t = il.reg(4, rn(insn, "ft")?);
    let cond2 = cond(il, 4, s, t);
    let v = merge(il, 4, cond1, cond2);
    il.append(il.set_reg(4, rn(insn, "br")?, v));
    len(insn)
}

fn lift_oeq_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    float_compares(insn, il, Il::float_compare_ordered, Il::float_compare_equal, Il::and_expr)
}
fn lift_ole_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    float_compares(insn, il, Il::float_compare_ordered, Il::float_compare_less_equal, Il::and_expr)
}
fn lift_olt_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    float_compares(insn, il, Il::float_compare_ordered, Il::float_compare_less_than, Il::and_expr)
}
fn lift_ueq_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    float_compares(insn, il, Il::float_compare_unordered, Il::float_compare_equal, Il::or_expr)
}
fn lift_ule_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    float_compares(insn, il, Il::float_compare_unordered, Il::float_compare_less_equal, Il::or_expr)
}
fn lift_ult_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    float_compares(insn, il, Il::float_compare_unordered, Il::float_compare_less_than, Il::or_expr)
}

fn lift_un_s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let s = il.reg(4, rn(insn, "fs")?);
    let t = il.reg(4, rn(insn, "ft")?);
    let cond1 = il.float_compare_unordered(4, s, t);
    il.append(il.set_reg(4, rn(insn, "br")?, cond1));
    len(insn)
}

// --------------------------------------------- float loads and stores ---

/// `add(4, reg as, const(4, insn.inline0(addr)))`.
fn va_imm(insn: &Insn, il: &Il) -> Result<E, Raise> {
    let a = il.reg(4, rn(insn, "as")?);
    let c = il.const_(4, inline0(insn)?);
    Ok(il.add(4, a, c))
}

/// `add(4, reg as, reg at)`.
fn va_reg(insn: &Insn, il: &Il) -> Result<E, Raise> {
    let a = il.reg(4, rn(insn, "as")?);
    let t = il.reg(4, rn(insn, "at")?);
    Ok(il.add(4, a, t))
}

fn float_load(insn: &Insn, il: &Il, va: E, dst: &str, update: bool) -> Lift {
    let l = il.load(4, va);
    il.append(il.set_reg(4, rn(insn, dst)?, l));
    if update {
        il.append(il.set_reg(4, rn(insn, "as")?, va));
    }
    len(insn)
}

fn float_store(insn: &Insn, il: &Il, va: E, src: &str, update: bool) -> Lift {
    let v = il.reg(4, rn(insn, src)?);
    il.append(il.store(4, va, v));
    if update {
        il.append(il.set_reg(4, rn(insn, "as")?, va));
    }
    len(insn)
}

fn lsiu(insn: &Insn, il: &Il, update: bool) -> Lift {
    let va = va_imm(insn, il)?;
    float_load(insn, il, va, "ft", update)
}
fn lsxu(insn: &Insn, il: &Il, update: bool) -> Lift {
    let va = va_reg(insn, il)?;
    float_load(insn, il, va, "fr", update)
}
fn ssiu(insn: &Insn, il: &Il, update: bool) -> Lift {
    let va = va_imm(insn, il)?;
    float_store(insn, il, va, "ft", update)
}
fn ssxu(insn: &Insn, il: &Il, update: bool) -> Lift {
    let va = va_reg(insn, il)?;
    float_store(insn, il, va, "fr", update)
}

fn lift_lsiu(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lsiu(insn, il, true)
}
fn lift_lsxu(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lsxu(insn, il, true)
}
fn lift_ssiu(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    ssiu(insn, il, true)
}
fn lift_ssxu(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    ssxu(insn, il, true)
}
fn lift_lsi(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lsiu(insn, il, false)
}
fn lift_lsx(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lsxu(insn, il, false)
}
fn lift_ssi(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    ssiu(insn, il, false)
}
fn lift_ssx(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    ssxu(insn, il, false)
}

// --------------------------------------------------------------- loops ---

/// `_lift_LOOP_simple`. Unreachable from the dispatcher (there is no
/// mnemonic `LOOP.simple`); kept so the loop workflow port can use it.
#[allow(dead_code)]
pub fn lift_loop_simple(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let cnt = il.reg(4, rn(insn, "as")?);
    let end_addr = addr as i64 + 4 + fv(insn, Field::Imm8)?;
    let false_label = il.new_label();
    let begin_label = il.new_label();
    let end_label = il.new_label();
    il.append(il.set_reg(4, reg("lcount")?, cnt));
    let c = il.const_(4, addr as i64 + 3);
    il.append(il.set_reg(4, reg("lbeg")?, c));
    let c = il.const_(4, end_addr);
    il.append(il.set_reg(4, reg("lend")?, c));
    il.mark_label(begin_label);
    let lc = il.reg(4, reg("lcount")?);
    let z = il.const_(4, 0);
    let cond = il.compare_equal(4, lc, z);
    il.append(il.if_expr(cond, end_label, false_label));
    il.mark_label(false_label);
    let lc = il.reg(4, reg("lcount")?);
    let m1 = il.const_(4, -1);
    let dec = il.add(4, lc, m1);
    il.append(il.set_reg(4, reg("lcount")?, dec));
    il.set_current_address(end_addr as u64);
    il.append(il.goto(begin_label));
    il.mark_label(end_label);
    il.set_current_address(addr);
    len(insn)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LoopType {
    Loop,
    Loopnez,
    Loopgtz,
}

/// `_lift_loop_instruction(insn, addr, il, data, loop_type)`.
fn loop_instruction(insn: &Insn, addr: u64, il: &Il, loop_type: LoopType) -> Lift {
    let count = il.reg(4, rn(insn, "as")?);
    let end = addr as i64 + 4 + fv(insn, Field::Imm8)?;
    let one = il.const_(4, 1);
    let dec = il.sub(4, count, one);
    il.append(il.set_reg(4, reg("lcount")?, dec));
    let c = il.const_(4, addr as i64 + insn.len as i64);
    il.append(il.set_reg(4, reg("lbeg")?, c));
    let c = il.const_(4, end);
    il.append(il.set_reg(4, reg("lend")?, c));
    if loop_type != LoopType::Loop {
        let skip = il.new_label();
        let body = il.new_label();
        let z = il.const_(4, 0);
        let condition = if loop_type == LoopType::Loopnez {
            il.compare_equal(4, count, z)
        } else {
            il.compare_signed_less_equal(4, count, z)
        };
        il.append(il.if_expr(condition, skip, body));
        il.mark_label(skip);
        let p = il.const_pointer(4, end);
        il.append(il.jump(p));
        il.mark_label(body);
    }
    len(insn)
}

fn lift_loop(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    loop_instruction(insn, addr, il, LoopType::Loop)
}
fn lift_loopnez(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    loop_instruction(insn, addr, il, LoopType::Loopnez)
}
fn lift_loopgtz(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    loop_instruction(insn, addr, il, LoopType::Loopgtz)
}

// ---------------------------------------------------- exception option ---

fn lift_ill(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    raise_exception(il, 0, addr)?;
    len(insn)
}

fn lift_syscall(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    raise_exception(il, 1, addr)?;
    len(insn)
}

/// `il.append(il.intrinsic([], name, []))`.
fn bare_intrinsic(insn: &Insn, il: &Il, name: &str) -> Lift {
    il.append(il.intrinsic(&[], regs::intrinsic(name)?, &[]));
    len(insn)
}

fn lift_excw(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    bare_intrinsic(insn, il, "exception_wait")
}

fn lift_rfe(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let ps = il.reg(4, reg("ps")?);
    let m = il.const_(4, 0xffff_ffef);
    let v = il.and_expr(4, ps, m);
    il.append(il.set_reg(4, reg("ps")?, v));
    let dest = il.reg(4, reg("epc1")?);
    il.append(il.ret(dest));
    len(insn)
}

fn lift_rfue(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    raise_exception(il, 0, addr)?;
    len(insn)
}

fn lift_rfde(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    double_return(il)?;
    len(insn)
}

// ---------------------------------------------------- interrupt options ---

fn lift_rfi(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let s = fv(insn, Field::S)?;
    if !(1..=7).contains(&s) {
        il.append(il.unimplemented());
        return len(insn);
    }
    let epc_level = il.reg(4, rn(insn, "epcs")?);
    // "eps1" is not a register: RFI 1 raises here with nothing appended.
    let eps = il.reg(4, regs::numbered("eps", s)?);
    il.append(il.set_reg(4, reg("ps")?, eps));
    il.append(il.ret(epc_level));
    len(insn)
}

/// `or(4, const(4, s), and(4, reg ps, const(4, 0xFFFFFFF0)))`.
fn ps_with_level(insn: &Insn, il: &Il) -> Result<E, Raise> {
    let ps = il.reg(4, reg("ps")?);
    let m = il.const_(4, 0xFFFF_FFF0);
    let ps_rest = il.and_expr(4, ps, m);
    let s = il.const_(4, fv(insn, Field::S)?);
    Ok(il.or_expr(4, s, ps_rest))
}

fn lift_rsil(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let ps_reg = il.reg(4, reg("ps")?);
    il.append(il.set_reg(4, rn(insn, "at")?, ps_reg));
    let result = ps_with_level(insn, il)?;
    il.append(il.set_reg(4, reg("ps")?, result));
    len(insn)
}

fn lift_waiti(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let result = ps_with_level(insn, il)?;
    il.append(il.set_reg(4, reg("ps")?, result));
    len(insn)
}

fn lift_rfme(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let dest = il.reg(4, reg("mepc")?);
    let meps = il.reg(4, reg("meps")?);
    il.append(il.set_reg(4, reg("ps")?, meps));
    il.append(il.ret(dest));
    len(insn)
}

// ----------------------------------------------------------- MAC16 loads ---

/// `_lift_mac_load(insn, addr, il, delta)`.
fn mac_load(insn: &Insn, il: &Il, delta: i64) -> Lift {
    // base = "a" + str(insn.s)
    let base = regs::numbered("a", fv(insn, Field::S)?)?;
    let b = il.reg(4, base);
    let d = il.const_(4, delta);
    let address = il.add(4, b, d);
    let l = il.load(4, address);
    // "m" + str(insn.r): m4..m15 do not exist, so r >= 4 raises here.
    let m = regs::numbered("m", fv(insn, Field::R)?)?;
    il.append(il.set_reg(4, m, l));
    il.append(il.set_reg(4, base, address));
    len(insn)
}

fn lift_ldinc(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    mac_load(insn, il, 4)
}
fn lift_lddec(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    mac_load(insn, il, -4)
}

// --------------------------------- multiprocessor synchronization option ---

fn lift_l32ai(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let va = va_imm(insn, il)?;
    let l = il.load(4, va);
    il.append(il.set_reg(4, rn(insn, "at")?, l));
    il.append(il.intrinsic(&[], regs::intrinsic("acquire")?, &[]));
    len(insn)
}

fn lift_s32ri(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let va = va_imm(insn, il)?;
    let v = il.reg(4, rn(insn, "at")?);
    il.append(il.store(4, va, v));
    // The reference emits "acquire" (not a release) after the store.
    il.append(il.intrinsic(&[], regs::intrinsic("acquire")?, &[]));
    len(insn)
}

// ---------------------------------------------- intrinsic-only helpers ---

/// `_lift_intrinsic_2param(insn, il, intrinsic)`.
fn intrinsic_2param(insn: &Insn, il: &Il, name: &str) -> Lift {
    let reg_as = il.reg(4, rn(insn, "as")?);
    let reg_at = il.reg(4, rn(insn, "at")?);
    il.append(il.intrinsic(&[], regs::intrinsic(name)?, &[reg_as, reg_at]));
    len(insn)
}

/// `_lift_intrinsic_1param(insn, il, intrinsic)`.
fn intrinsic_1param(insn: &Insn, il: &Il, name: &str) -> Lift {
    let reg_as = il.reg(4, rn(insn, "as")?);
    il.append(il.intrinsic(&[], regs::intrinsic(name)?, &[reg_as]));
    len(insn)
}

/// `_lift_intrinsic_1param_1result(insn, il, intrinsic)`: also builds an
/// unused `reg(4, at)` expression, as the reference does.
fn intrinsic_1param_1result(insn: &Insn, il: &Il, name: &str) -> Lift {
    let reg_as = il.reg(4, rn(insn, "as")?);
    let _reg_at = il.reg(4, rn(insn, "at")?);
    let out: R = rn(insn, "at")?;
    il.append(il.intrinsic(&[out], regs::intrinsic(name)?, &[reg_as]));
    len(insn)
}

/// `_lift_cache_intrinsic_imm8` (`imm8 << 2`) / `_imm4` (`imm4 << 4`).
fn cache_intrinsic(insn: &Insn, il: &Il, name: &str, field: Field, shift: u32) -> Lift {
    let a = il.reg(4, rn(insn, "as")?);
    let c = il.const_(4, fv(insn, field)? << shift);
    let va = il.add(4, a, c);
    il.append(il.intrinsic(&[], regs::intrinsic(name)?, &[va]));
    len(insn)
}

fn cache_imm8(insn: &Insn, il: &Il, name: &str) -> Lift {
    cache_intrinsic(insn, il, name, Field::Imm8, 2)
}
fn cache_imm4(insn: &Insn, il: &Il, name: &str) -> Lift {
    cache_intrinsic(insn, il, name, Field::Imm4, 4)
}

// ------------------------------------------------ conditional store ---

fn lift_s32c1i(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let reg_at = il.reg(4, rn(insn, "at")?);
    let reg_scompare = il.reg(4, reg("scompare1")?);
    let a = il.reg(4, rn(insn, "as")?);
    let c = il.const_(4, fv(insn, Field::Imm8)? << 2);
    let va = il.add(4, a, c);
    let out = rn(insn, "at")?;
    let intr = regs::intrinsic("store_32bit_compare_conditional")?;
    il.append(il.intrinsic(&[out], intr, &[va, reg_at, reg_scompare]));
    len(insn)
}

// ------------------------------------------------------- debug option ---

fn lift_break(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    bare_intrinsic(insn, il, "debug_break")
}
fn lift_rfdd(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    bare_intrinsic(insn, il, "return_from_debug_and_dispatch")
}
fn lift_rfdo(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    bare_intrinsic(insn, il, "return_from_debug_operation")
}

// ------------------------------------------- cache / TLB lambdas ---

macro_rules! intrinsic_lambdas {
    ($($fn_name:ident => $helper:ident($intr:literal),)*) => {
        $(
            fn $fn_name(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
                $helper(insn, il, $intr)
            }
        )*
    };
}

intrinsic_lambdas! {
    lift_dhi => cache_imm8("data_cache_hit_invalidate"),
    lift_dhwb => cache_imm8("data_cache_hit_writeback"),
    lift_dhwbi => cache_imm8("data_cache_hit_writeback_invalidate"),
    lift_dpfr => cache_imm8("data_cache_prefetch_for_read"),
    lift_dpfro => cache_imm8("data_cache_prefetch_for_read_once"),
    lift_dpfw => cache_imm8("data_cache_prefetch_for_write"),
    lift_dpfwo => cache_imm8("data_cache_prefetch_for_write_once"),
    lift_dii => cache_imm8("data_cache_index_invalidate"),
    lift_diwb => cache_imm4("data_cache_index_writeback"),
    lift_diwbi => cache_imm4("data_cache_index_writeback_invalidate"),
    lift_dhu => cache_imm4("data_cache_hit_unlock"),
    lift_diu => cache_imm4("data_cache_index_unlock"),
    lift_dpfl => cache_imm4("data_cache_prefetch_and_lock"),
    lift_ldct => intrinsic_1param_1result("load_data_cache_tag"),
    lift_sdct => intrinsic_2param("store_data_cache_tag"),
    lift_ihi => cache_imm8("instruction_cache_hit_invalidate"),
    lift_iii => cache_imm8("instruction_cache_index_invalidate"),
    lift_ipf => cache_imm8("instruction_cache_prefetch"),
    lift_ihu => cache_imm4("instruction_cache_hit_unlock"),
    lift_iiu => cache_imm4("instruction_cache_index_unlock"),
    lift_ipfl => cache_imm4("instruction_cache_prefetch_and_lock"),
    lift_lict => intrinsic_1param_1result("load_instruction_cache_tag"),
    lift_licw => intrinsic_1param_1result("load_instruction_cache_word"),
    lift_sict => intrinsic_2param("store_instruction_cache_tag"),
    lift_sicw => intrinsic_2param("store_instruction_cache_word"),
    lift_idtlb => intrinsic_1param("invalidate_data_TLB_entry"),
    lift_iitlb => intrinsic_1param("invalidate_instruciton_TLB_entry"),
    lift_pdtlb => intrinsic_1param_1result("probe_data_TLB"),
    lift_pitlb => intrinsic_1param_1result("probe_instruction_TLB"),
    lift_rdtlb0 => intrinsic_1param_1result("read_data_TLB_entry_virtual"),
    lift_rdtlb1 => intrinsic_1param_1result("read_data_TLB_entry_translation"),
    lift_ritlb0 => intrinsic_1param_1result("read_instruction_TLB_entry_virtual"),
    lift_ritlb1 => intrinsic_1param_1result("read_instruction_TLB_entry_translation"),
    lift_wdtlb => intrinsic_2param("write_data_TLB_entry"),
    lift_witlb => intrinsic_2param("write_instruction_TLB_entry"),
}

// ------------------------------------------------- MAC16 arithmetic ---

/// `il.reg`/`il.set_reg` on a MAC16 attribute string (`"m4"` raises).
fn mac_reg(r: Option<MacReg>) -> Result<R, Raise> {
    let r = r.ok_or(Raise::Other("_lift_mac_arithmetic: register is None"))?;
    reg(r.name())
}

/// `_lift_mac_arithmetic`.
pub fn lift_mac_arithmetic(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let load_delta = insn.mac_load_delta();
    let mut address = None;
    if let Some(delta) = load_delta {
        let base = il.reg(4, mac_reg(insn.mac_base())?);
        let d = il.const_(4, delta as i64);
        let a = il.add(4, base, d);
        address = Some(a);
        let l = il.load(4, a);
        il.append(il.set_reg(4, temp(29), l));
    }
    let op = insn.mac_operation().ok_or(Raise::Other("mac_operation is None"))?;
    let half = insn.mac_half().ok_or(Raise::Other("mac_half is None"))?;
    let operand = |register: Option<MacReg>, upper: bool| -> Result<E, Raise> {
        let mut value = il.reg(4, mac_reg(register)?);
        if upper {
            let sh = il.const_(1, 16);
            value = il.logical_shift_right(4, value, sh);
        }
        let h = il.low_part(2, value);
        Ok(if op == MacOperation::Umul { il.zero_extend(8, h) } else { il.sign_extend(8, h) })
    };
    let left = operand(insn.mac_left(), half & 1 != 0)?;
    let right = operand(insn.mac_right(), half & 2 != 0)?;
    let product = il.mult(8, left, right);
    let mut result = product;
    if matches!(op, MacOperation::Mula | MacOperation::Muls) {
        let lo = il.reg(4, reg("acclo")?);
        let lo = il.zero_extend(8, lo);
        let hi = il.reg(1, reg("acchi")?);
        let hi = il.zero_extend(8, hi);
        let sh = il.const_(1, 32);
        let hi = il.shift_left(8, hi, sh);
        let accumulator = il.or_expr(8, lo, hi);
        result = if op == MacOperation::Mula {
            il.add(8, accumulator, product)
        } else {
            il.sub(8, accumulator, product)
        };
    }
    il.append(il.set_reg(8, temp(28), result));
    let t = il.reg(8, temp(28));
    let lo = il.low_part(4, t);
    il.append(il.set_reg(4, reg("acclo")?, lo));
    let t = il.reg(8, temp(28));
    let sh = il.const_(1, 32);
    let hi = il.logical_shift_right(8, t, sh);
    let hi = il.low_part(1, hi);
    il.append(il.set_reg(1, reg("acchi")?, hi));
    if let Some(address) = address {
        il.append(il.set_reg(4, mac_reg(insn.mac_base())?, address));
        let t = il.reg(4, temp(29));
        il.append(il.set_reg(4, mac_reg(insn.mac_destination())?, t));
    }
    len(insn)
}
