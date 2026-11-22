//! Port of the reference `window_bank.py`, `window_exceptions.py` and the
//! `lifter.py` section from "Special register instructions" through
//! `_lift_QUOS` (windowed calls, RSR/WSR/XSR, RUR/WUR, MUL16/MULL/MULSH/MULUH,
//! REM*/QUO*).
//!
//! Every function issues the builder calls of its Python original in Python's
//! evaluation order (arguments left to right, innermost first). Odd behaviour
//! of the reference is kept; see `LIFTER_QUIRKS.window.md`.

use xtensa_isa::{Field, Insn};

use super::common::{rn, target, Handler};
use super::{Lift, Raise};
use crate::il::{temp, Il, E, R};
use crate::regs;

/// `ILInstructionAttribute.ILTransparentCopy`.
pub const IL_TRANSPARENT_COPY: u32 = 0x1000;

/// Reserved synthetic address of the shared window-overflow block.
const SHARED_OVERFLOW_ADDRESS: u64 = 0x1_0000_0000;

fn reg(name: &str) -> Result<R, Raise> {
    regs::reg(name)
}

fn a(n: i64) -> Result<R, Raise> {
    regs::numbered("a", n)
}

// ------------------------------------------------------- window_bank.py ---

/// `_dispatch(il, selector, action)`.
fn dispatch(il: &Il, selector: E, mut action: impl FnMut(i64) -> Result<(), Raise>) -> Result<(), Raise> {
    let end = il.new_label();
    for window in 0..16i64 {
        let (matched, next_window) = (il.new_label(), il.new_label());
        let c = il.const_(4, window);
        let cond = il.compare_equal(4, selector, c);
        il.append(il.if_expr(cond, matched, next_window));
        il.mark_label(matched);
        action(window)?;
        il.append(il.goto(end));
        il.mark_label(next_window);
    }
    il.mark_label(end);
    Ok(())
}

/// `rotate_bank(il, new_window)`: explicit 64-register bank rotation.
pub fn rotate_bank(il: &Il, new_window: E) -> Result<(), Raise> {
    let c15 = il.const_(4, 15);
    let v = il.and_expr(4, new_window, c15);
    il.append(il.set_reg(4, temp(24), v));
    let wb = il.reg(4, reg("windowbase")?);
    let c15 = il.const_(4, 15);
    let old = il.and_expr(4, wb, c15);
    dispatch(il, old, |window| {
        for i in 0..16i64 {
            let src = il.reg(4, a(i)?);
            let dst = regs::numbered("ar", (window * 4 + i) % 64)?;
            il.append(il.set_reg(4, dst, src));
        }
        Ok(())
    })?;
    let t = il.reg(4, temp(24));
    il.append(il.set_reg(4, reg("windowbase")?, t));
    let sel = il.reg(4, reg("windowbase")?);
    dispatch(il, sel, |window| {
        for i in 0..16i64 {
            let src = il.reg(4, regs::numbered("ar", (window * 4 + i) % 64)?);
            il.append(il.set_reg(4, a(i)?, src));
        }
        Ok(())
    })?;
    il.append(il.nop());
    Ok(())
}

/// `rotate_bank_compact(il, new_window)` (unused by the reference lifter).
pub fn rotate_bank_compact(il: &Il, new_window: E) -> Result<(), Raise> {
    let c15 = il.const_(4, 15);
    let v = il.and_expr(4, new_window, c15);
    il.append(il.set_reg(4, temp(24), v));
    let z = il.const_(4, 0);
    il.append(il.set_reg(4, reg("bank_top")?, z));
    let index = |window: E, i: i64| {
        let c2 = il.const_(1, 2);
        let sh = il.shift_left(4, window, c2);
        let ci = il.const_(4, i);
        let ad = il.add(4, sh, ci);
        let c63 = il.const_(4, 63);
        il.and_expr(4, ad, c63)
    };
    for i in 0..16i64 {
        let wb = il.reg(4, reg("windowbase")?);
        let idx = index(wb, i);
        let v = il.reg(4, a(i)?);
        il.append(il.set_reg_stack_top_relative(4, idx, v));
    }
    let t = il.reg(4, temp(24));
    il.append(il.set_reg(4, reg("windowbase")?, t));
    for i in 0..16i64 {
        let wb = il.reg(4, reg("windowbase")?);
        let idx = index(wb, i);
        let v = il.reg_stack_top_relative(4, idx);
        il.append(il.set_reg(4, a(i)?, v));
    }
    Ok(())
}

// -------------------------------------------------- window_exceptions.py ---

/// `window_bit(il, displacement)`: WindowStart bit at WindowBase+displacement.
pub fn window_bit(il: &Il, displacement: i64) -> Result<E, Raise> {
    let wb = il.reg(4, reg("windowbase")?);
    let d = il.const_(4, displacement);
    let sum = il.add(4, wb, d);
    let c15 = il.const_(4, 15);
    let index = il.and_expr(4, sum, c15);
    let ws = il.reg(4, reg("windowstart")?);
    let sh = il.logical_shift_right(4, ws, index);
    let c1 = il.const_(4, 1);
    let bit = il.and_expr(4, sh, c1);
    let c0 = il.const_(4, 0);
    Ok(il.compare_not_equal(4, bit, c0))
}

/// `ps = ((ps & 0xfffff0ff) | (<owb> << 8)) | 16`, as the reference builds it.
fn set_ps_exception(il: &Il, owb: impl FnOnce() -> Result<E, Raise>) -> Result<(), Raise> {
    let ps = il.reg(4, reg("ps")?);
    let m = il.const_(4, 0xfffff0ff);
    let lo = il.and_expr(4, ps, m);
    let w = owb()?;
    let c8 = il.const_(1, 8);
    let sh = il.shift_left(4, w, c8);
    let o = il.or_expr(4, lo, sh);
    let c16 = il.const_(4, 16);
    let v = il.or_expr(4, o, c16);
    il.append(il.set_reg(4, reg("ps")?, v));
    Ok(())
}

/// `window_check(il, maximum_group, address)` from window_exceptions.py.
/// `maximum_group` is an expression index.
pub fn window_check(il: &Il, maximum_group: u64, address: u64) -> Result<(), Raise> {
    let (normal, inspect, exception) = (il.new_label(), il.new_label(), il.new_label());
    let ps = il.reg(4, reg("ps")?);
    let m = il.const_(4, 0x40010);
    let and = il.and_expr(4, ps, m);
    let v = il.const_(4, 0x40000);
    let enabled = il.compare_equal(4, and, v);
    il.append(il.if_expr(enabled, inspect, normal));
    il.mark_label(inspect);
    for group in 1..=3i64 {
        let (hit, next_group) = (il.new_label(), il.new_label());
        let g = il.const_(4, group);
        let ge = il.compare_unsigned_greater_equal(4, maximum_group, g);
        let bit = window_bit(il, group)?;
        let condition = il.and_expr(1, ge, bit);
        il.append(il.if_expr(condition, hit, next_group));
        il.mark_label(hit);
        let g = il.const_(4, group);
        il.append(il.set_reg(4, temp(25), g));
        il.append(il.goto(exception));
        il.mark_label(next_group);
    }
    il.append(il.goto(normal));
    il.mark_label(exception);
    set_ps_exception(il, || Ok(il.reg(4, reg("windowbase")?)))?;
    let pc = il.const_pointer(4, address as i64);
    il.append(il.set_reg(4, reg("epc1")?, pc));
    if let Some(shared) = il.get_label_for_address(SHARED_OVERFLOW_ADDRESS) {
        il.append(il.goto(shared));
    } else {
        il.add_label_for_address(SHARED_OVERFLOW_ADDRESS);
        let shared = il
            .get_label_for_address(SHARED_OVERFLOW_ADDRESS)
            .ok_or(Raise::Other("window_check: assert shared is not None"))?;
        il.mark_label(shared);
        let wb = il.reg(4, reg("windowbase")?);
        let t = il.reg(4, temp(25));
        let nw = il.add(4, wb, t);
        rotate_bank(il, nw)?;
        for (offset, vector) in [(1i64, 4), (2, 8)] {
            let (hit, next_vector) = (il.new_label(), il.new_label());
            let bit = window_bit(il, offset)?;
            il.append(il.if_expr(bit, hit, next_vector));
            il.mark_label(hit);
            let dest = il.reg(4, reg(&format!("windowoverflow{vector}"))?);
            il.append(il.jump(dest));
            il.mark_label(next_vector);
        }
        let dest = il.reg(4, reg("windowoverflow12")?);
        il.append(il.jump(dest));
    }
    il.mark_label(normal);
    Ok(())
}

/// `window_return(il, address)`: RETW with ABI-local normal return and
/// physical-bank underflow transfer.
pub fn window_return(il: &Il, address: u64) -> Result<(), Raise> {
    let a0 = il.reg(4, reg("a0")?);
    let m = il.const_(4, 0x3fffffff);
    let lo = il.and_expr(4, a0, m);
    let hi = il.const_(4, (address & 0xc000_0000) as i64);
    let v = il.or_expr(4, lo, hi);
    il.append(il.set_reg(4, temp(20), v));
    let wb = il.reg(4, reg("windowbase")?);
    il.append(il.set_reg(4, temp(21), wb));
    let a0 = il.reg(4, reg("a0")?);
    let c30 = il.const_(1, 30);
    let v = il.logical_shift_right(4, a0, c30);
    il.append(il.set_reg(4, temp(22), v));
    let (valid, invalid, check) = (il.new_label(), il.new_label(), il.new_label());
    let ps = il.reg(4, reg("ps")?);
    let m = il.const_(4, 0x40010);
    let and = il.and_expr(4, ps, m);
    let c = il.const_(4, 0x40000);
    let en = il.compare_equal(4, and, c);
    let t22 = il.reg(4, temp(22));
    let c0 = il.const_(4, 0);
    let nz = il.compare_not_equal(4, t22, c0);
    let condition = il.and_expr(1, en, nz);
    il.append(il.if_expr(condition, check, invalid));
    il.mark_label(check);
    for distance in 1..=3i64 {
        let (found, onward) = (il.new_label(), il.new_label());
        let bit = window_bit(il, -distance)?;
        il.append(il.if_expr(bit, found, onward));
        il.mark_label(found);
        let t22 = il.reg(4, temp(22));
        let d = il.const_(4, distance);
        let eq = il.compare_equal(4, t22, d);
        il.append(il.if_expr(eq, valid, invalid));
        il.mark_label(onward);
    }
    let underflow = il.new_label();
    il.append(il.goto(underflow));
    il.mark_label(invalid);
    il.append(il.trap(0));
    il.mark_label(valid);
    let c1 = il.const_(4, 1);
    let wb = il.reg(4, reg("windowbase")?);
    let mask = il.shift_left(4, c1, wb);
    let ws = il.reg(4, reg("windowstart")?);
    let ff = il.const_(4, 0xffffffff);
    let inv = il.xor_expr(4, mask, ff);
    let v = il.and_expr(4, ws, inv);
    il.append(il.set_reg(4, reg("windowstart")?, v));
    let wb = il.reg(4, reg("windowbase")?);
    let t22 = il.reg(4, temp(22));
    let s = il.sub(4, wb, t22);
    let c15 = il.const_(4, 15);
    let v = il.and_expr(4, s, c15);
    il.append(il.set_reg(4, reg("windowbase")?, v));
    let t20 = il.reg(4, temp(20));
    il.append(il.ret(t20));
    il.mark_label(underflow);
    set_ps_exception(il, || Ok(il.reg(4, temp(21))))?;
    let pc = il.const_pointer(4, address as i64);
    il.append(il.set_reg(4, reg("epc1")?, pc));
    let wb = il.reg(4, reg("windowbase")?);
    let t22 = il.reg(4, temp(22));
    let nw = il.sub(4, wb, t22);
    rotate_bank(il, nw)?;
    for (increment, vector) in [(1i64, 4), (2, 8)] {
        let (found, onward) = (il.new_label(), il.new_label());
        let t22 = il.reg(4, temp(22));
        let c = il.const_(4, increment);
        let eq = il.compare_equal(4, t22, c);
        il.append(il.if_expr(eq, found, onward));
        il.mark_label(found);
        let dest = il.reg(4, reg(&format!("windowunderflow{vector}"))?);
        il.append(il.jump(dest));
        il.mark_label(onward);
    }
    let dest = il.reg(4, reg("windowunderflow12")?);
    il.append(il.jump(dest));
    Ok(())
}

// general_exception.py is ported in `fp_mac::general_exception`; MOVSP uses it.
use super::fp_mac::general_exception::raise_exception;

// ------------------------------------------- special / user registers ---

/// `insn._special_reg_map.get(insn.sr)`, then `"sr" + str(insn.sr)` if absent,
/// else the lower-cased table name.
fn sr_name(insn: &Insn) -> String {
    let sr = insn.field(Field::Sr);
    match sr.and_then(|v| xtensa_isa::regs::special_reg(v as u8)) {
        Some((name, _)) => name.to_lowercase(),
        None => match sr {
            Some(v) => format!("sr{v}"),
            None => "srNone".to_string(),
        },
    }
}

/// Same for `_user_reg_map` / `"ur" + str(insn.sr)`.
fn ur_name(insn: &Insn) -> String {
    let sr = insn.field(Field::Sr);
    match sr.and_then(|v| xtensa_isa::regs::user_reg(v as u8)) {
        Some((name, _)) => name.to_lowercase(),
        None => match sr {
            Some(v) => format!("ur{v}"),
            None => "urNone".to_string(),
        },
    }
}

fn is_acchi(insn: &Insn) -> bool {
    insn.field(Field::Sr) == Some(17)
}

/// `_lift_RSR`.
pub fn lift_rsr(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let sr = sr_name(insn);
    let value = if is_acchi(insn) {
        let r = il.reg(1, reg(&sr)?);
        il.sign_extend(4, r)
    } else {
        il.reg(4, reg(&sr)?)
    };
    il.append(il.set_reg(4, rn(insn, "at")?, value));
    Ok(insn.len as usize)
}

/// `_lift_WSR`.
pub fn lift_wsr(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let sr = sr_name(insn);
    let value = il.reg(4, rn(insn, "at")?);
    let e = if is_acchi(insn) {
        let lp = il.low_part(1, value);
        il.set_reg(1, reg(&sr)?, lp)
    } else {
        il.set_reg(4, reg(&sr)?, value)
    };
    il.append(e);
    Ok(insn.len as usize)
}

/// `_lift_XSR`.
pub fn lift_xsr(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let sr = sr_name(insn);
    let t = temp(0);
    let at_reg = rn(insn, "at")?;
    let old = if is_acchi(insn) {
        let r = il.reg(1, reg(&sr)?);
        il.sign_extend(4, r)
    } else {
        il.reg(4, reg(&sr)?)
    };
    il.append(il.set_reg(4, t, old));
    let incoming = il.reg(4, at_reg);
    let e = if is_acchi(insn) {
        let lp = il.low_part(1, incoming);
        il.set_reg(1, reg(&sr)?, lp)
    } else {
        il.set_reg(4, reg(&sr)?, incoming)
    };
    il.append(e);
    let tv = il.reg(4, t);
    il.append(il.set_reg(4, at_reg, tv));
    Ok(insn.len as usize)
}

/// `_lift_RUR`.
pub fn lift_rur(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let ur = ur_name(insn);
    let dst = rn(insn, "at")?;
    let v = il.reg(4, reg(&ur)?);
    il.append(il.set_reg(4, dst, v));
    Ok(insn.len as usize)
}

/// `_lift_WUR`.
pub fn lift_wur(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let ur = ur_name(insn);
    let v = il.reg(4, rn(insn, "at")?);
    il.append(il.set_reg(4, reg(&ur)?, v));
    Ok(insn.len as usize)
}

// ------------------------------------------------------ windowed calls ---

/// `_lift_CALL0`.
pub fn lift_call0(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let dest = il.const_(4, target(insn, addr)?);
    il.append(il.call(dest));
    Ok(insn.len as usize)
}

/// `_lift_CALLX0`.
pub fn lift_callx0(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let dest = il.reg(4, rn(insn, "as")?);
    il.append(il.call(dest));
    Ok(insn.len as usize)
}

/// `_window_copy(il, destination, source)`: a SET_REG with ILTransparentCopy.
pub fn window_copy(il: &Il, destination: R, source: E) {
    let expression = il.set_reg(4, destination, source);
    il.set_expr_attributes(expression, IL_TRANSPARENT_COPY);
    il.append(expression);
}

/// `_window_call(il, destination, n)`.
pub fn window_call(il: &Il, destination: E, n: i64) -> Result<(), Raise> {
    let ps = il.reg(4, reg("ps")?);
    let m = il.const_(4, 0xfffcffff);
    let and = il.and_expr(4, ps, m);
    let c = il.const_(4, (n / 4) << 16);
    let v = il.or_expr(4, and, c);
    il.append(il.set_reg(4, reg("ps")?, v));
    for i in 0..n {
        let src = il.reg(4, a(i)?);
        window_copy(il, temp(i as u32), src);
    }
    for i in 0..16 - n {
        let src = il.reg(4, a(i + n)?);
        window_copy(il, a(i)?, src);
    }
    let src = il.reg(4, temp(1));
    window_copy(il, reg("a1")?, src);
    il.append(il.call(destination));
    for i in (0..16 - n).rev() {
        let src = il.reg(4, a(i)?);
        window_copy(il, a(i + n)?, src);
    }
    for i in 0..n {
        let src = il.reg(4, temp(i as u32));
        window_copy(il, a(i)?, src);
    }
    Ok(())
}

/// `_lift_CALLXn(insn, addr, il, n)`.
pub fn lift_callxn(insn: &Insn, _addr: u64, il: &Il, n: i64) -> Lift {
    let v = il.reg(4, rn(insn, "as")?);
    il.append(il.set_reg(4, temp(16), v));
    let dest = il.reg(4, temp(16));
    window_call(il, dest, n)?;
    Ok(insn.len as usize)
}

/// `_lift_CALLn(insn, addr, il, n)`.
pub fn lift_calln(insn: &Insn, addr: u64, il: &Il, n: i64) -> Lift {
    let dest = il.const_pointer(4, target(insn, addr)?);
    window_call(il, dest, n)?;
    Ok(insn.len as usize)
}

fn lift_callx4(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lift_callxn(insn, addr, il, 4)
}
fn lift_callx8(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lift_callxn(insn, addr, il, 8)
}
fn lift_callx12(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lift_callxn(insn, addr, il, 12)
}
fn lift_call4(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lift_calln(insn, addr, il, 4)
}
fn lift_call8(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lift_calln(insn, addr, il, 8)
}
fn lift_call12(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lift_calln(insn, addr, il, 12)
}

/// `_lift_RET` (also `_lift_RET_N`).
pub fn lift_ret(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let dest = il.reg(4, reg("a0")?);
    il.append(il.ret(dest));
    Ok(insn.len as usize)
}

/// `_lift_RETW` (also `_lift_RETW_N`).
pub fn lift_retw(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    window_return(il, addr)?;
    Ok(insn.len as usize)
}

/// `(ps >> 16) & 3`, the CALLINC field.
fn callinc(il: &Il) -> Result<E, Raise> {
    let ps = il.reg(4, reg("ps")?);
    let c16 = il.const_(1, 16);
    let sh = il.logical_shift_right(4, ps, c16);
    let c3 = il.const_(4, 3);
    Ok(il.and_expr(4, sh, c3))
}

/// `_lift_ENTRY`.
pub fn lift_entry(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let group = callinc(il)?;
    window_check(il, group, addr)?;
    let dst = rn(insn, "as")?;
    let a1 = il.reg(4, reg("a1")?);
    let imm = il.const_(4, insn.inline0().ok_or(Raise::Other("ENTRY: inline0 is None"))?);
    let v = il.sub(4, a1, imm);
    il.append(il.set_reg(4, dst, v));
    let increment = callinc(il)?;
    let wb = il.reg(4, reg("windowbase")?);
    let s = il.add(4, wb, increment);
    let c15 = il.const_(4, 15);
    let v = il.and_expr(4, s, c15);
    il.append(il.set_reg(4, reg("windowbase")?, v));
    let ws = il.reg(4, reg("windowstart")?);
    let c1 = il.const_(4, 1);
    let wb = il.reg(4, reg("windowbase")?);
    let sh = il.shift_left(4, c1, wb);
    let v = il.or_expr(4, ws, sh);
    il.append(il.set_reg(4, reg("windowstart")?, v));
    Ok(insn.len as usize)
}

/// `_window_exception_return(insn, il, underflow)`.
fn window_exception_return(insn: &Insn, il: &Il, underflow: bool) -> Lift {
    let ps = il.reg(4, reg("ps")?);
    let m = il.const_(4, 0xffffffef);
    let v = il.and_expr(4, ps, m);
    il.append(il.set_reg(4, reg("ps")?, v));
    let c1 = il.const_(4, 1);
    let wb = il.reg(4, reg("windowbase")?);
    let mask = il.shift_left(4, c1, wb);
    let ws = il.reg(4, reg("windowstart")?);
    let value = if underflow {
        il.or_expr(4, ws, mask)
    } else {
        let ff = il.const_(4, 0xffffffff);
        let inv = il.xor_expr(4, mask, ff);
        il.and_expr(4, ws, inv)
    };
    il.append(il.set_reg(4, reg("windowstart")?, value));
    let ps = il.reg(4, reg("ps")?);
    let c8 = il.const_(1, 8);
    let sh = il.logical_shift_right(4, ps, c8);
    let c15 = il.const_(4, 15);
    let nw = il.and_expr(4, sh, c15);
    rotate_bank(il, nw)?;
    let epc = il.reg(4, reg("epc1")?);
    il.append(il.ret(epc));
    Ok(insn.len as usize)
}

/// `_lift_RFWO`.
pub fn lift_rfwo(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    window_exception_return(insn, il, false)
}

/// `_lift_RFWU`.
pub fn lift_rfwu(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    window_exception_return(insn, il, true)
}

/// `_lift_MOVSP`.
pub fn lift_movsp(insn: &Insn, addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let (mv, exception) = (il.new_label(), il.new_label());
    let b1 = window_bit(il, -1)?;
    let b2 = window_bit(il, -2)?;
    let o = il.or_expr(1, b1, b2);
    let b3 = window_bit(il, -3)?;
    let present = il.or_expr(1, o, b3);
    il.append(il.if_expr(present, mv, exception));
    il.mark_label(exception);
    raise_exception(il, 5, addr)?;
    il.mark_label(mv);
    // return _lift_MOV_N(insn, addr, il)
    let dst = rn(insn, "at")?;
    let v = il.reg(4, rn(insn, "as")?);
    il.append(il.set_reg(4, dst, v));
    Ok(insn.len as usize)
}

/// `_lift_ROTW`.
pub fn lift_rotw(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let wb = il.reg(4, reg("windowbase")?);
    let imm = il.const_(4, insn.rotw_simm4().ok_or(Raise::Other("ROTW: rotw_simm4 is None"))?);
    let nw = il.add(4, wb, imm);
    rotate_bank(il, nw)?;
    Ok(insn.len as usize)
}

fn l32e_address(insn: &Insn, il: &Il) -> Result<E, Raise> {
    let s = il.reg(4, rn(insn, "as")?);
    let imm = il.const_(4, insn.inline0().ok_or(Raise::Other("L32E/S32E: inline0 is None"))?);
    Ok(il.add(4, s, imm))
}

/// `_lift_L32E`.
pub fn lift_l32e(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let address = l32e_address(insn, il)?;
    let dst = rn(insn, "at")?;
    let v = il.load(4, address);
    il.append(il.set_reg(4, dst, v));
    Ok(insn.len as usize)
}

/// `_lift_S32E`.
pub fn lift_s32e(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let address = l32e_address(insn, il)?;
    let v = il.reg(4, rn(insn, "at")?);
    il.append(il.store(4, address, v));
    Ok(insn.len as usize)
}

// ------------------------------------------------- multiply / divide ---

fn lift_mul16(insn: &Insn, il: &Il, signed: bool) -> Lift {
    let dst = rn(insn, "ar")?;
    let ext = |e: E| if signed { il.sign_extend(4, e) } else { il.zero_extend(4, e) };
    let s = il.reg(4, rn(insn, "as")?);
    let s = ext(il.low_part(2, s));
    let t = il.reg(4, rn(insn, "at")?);
    let t = ext(il.low_part(2, t));
    let v = il.mult(4, s, t);
    il.append(il.set_reg(4, dst, v));
    Ok(insn.len as usize)
}

/// `_lift_MUL16S`.
pub fn lift_mul16s(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lift_mul16(insn, il, true)
}

/// `_lift_MUL16U`.
pub fn lift_mul16u(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lift_mul16(insn, il, false)
}

type BinOp = fn(&Il, usize, E, E) -> E;

/// `ar = op(4, as, at)`.
fn binop(insn: &Insn, il: &Il, op: BinOp) -> Lift {
    let dst = rn(insn, "ar")?;
    let s = il.reg(4, rn(insn, "as")?);
    let t = il.reg(4, rn(insn, "at")?);
    let v = op(il, 4, s, t);
    il.append(il.set_reg(4, dst, v));
    Ok(insn.len as usize)
}

/// `_lift_MULL`.
pub fn lift_mull(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    binop(insn, il, Il::mult)
}

fn lift_mul_high(insn: &Insn, il: &Il, op: BinOp) -> Lift {
    let s = il.reg(4, rn(insn, "as")?);
    let t = il.reg(4, rn(insn, "at")?);
    let tmp = op(il, 4, s, t);
    let c32 = il.const_(1, 32);
    let sh = il.logical_shift_right(8, tmp, c32);
    let result = il.low_part(4, sh);
    il.append(il.set_reg(4, rn(insn, "ar")?, result));
    Ok(insn.len as usize)
}

/// `_lift_MULSH`.
pub fn lift_mulsh(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lift_mul_high(insn, il, Il::mult_double_prec_signed)
}

/// `_lift_MULUH`.
pub fn lift_muluh(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    lift_mul_high(insn, il, Il::mult_double_prec_unsigned)
}

/// `_lift_REMU`.
pub fn lift_remu(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    binop(insn, il, Il::mod_unsigned)
}

/// `_lift_REMS`.
pub fn lift_rems(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    binop(insn, il, Il::mod_signed)
}

/// `_lift_QUOU`.
pub fn lift_quou(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    binop(insn, il, Il::div_unsigned)
}

/// `_lift_QUOS`.
pub fn lift_quos(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    binop(insn, il, Il::div_signed)
}

/// Python handler names (mnemonic with '.' replaced by '_') ported here.
pub fn handler(name: &str) -> Option<Handler> {
    Some(match name {
        "RSR" => lift_rsr,
        "WSR" => lift_wsr,
        "XSR" => lift_xsr,
        "RUR" => lift_rur,
        "WUR" => lift_wur,
        "CALL0" => lift_call0,
        "CALLX0" => lift_callx0,
        "CALLX4" => lift_callx4,
        "CALLX8" => lift_callx8,
        "CALLX12" => lift_callx12,
        "CALL4" => lift_call4,
        "CALL8" => lift_call8,
        "CALL12" => lift_call12,
        "RET" | "RET_N" => lift_ret,
        "RETW" | "RETW_N" => lift_retw,
        "ENTRY" => lift_entry,
        "RFWO" => lift_rfwo,
        "RFWU" => lift_rfwu,
        "MOVSP" => lift_movsp,
        "ROTW" => lift_rotw,
        "L32E" => lift_l32e,
        "S32E" => lift_s32e,
        "MUL16S" => lift_mul16s,
        "MUL16U" => lift_mul16u,
        "MULL" => lift_mull,
        "MULSH" => lift_mulsh,
        "MULUH" => lift_muluh,
        "REMU" => lift_remu,
        "REMS" => lift_rems,
        "QUOU" => lift_quou,
        "QUOS" => lift_quos,
        _ => return None,
    })
}
