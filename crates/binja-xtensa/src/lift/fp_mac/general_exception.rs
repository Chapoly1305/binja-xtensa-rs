//! Port of `general_exception.py` (Exception Option 2 state transitions,
//! ISA section 4.4.1.10).

use crate::il::{Il, Label};
use crate::lift::Raise;
use crate::regs::reg;

/// `raise_exception(il, cause, address)`.
pub fn raise_exception(il: &Il, cause: i64, address: u64) -> Result<(), Raise> {
    // double, normal, use_depc, use_epc = [LowLevelILLabel() for _ in range(4)]
    let double = il.new_label();
    let normal = il.new_label();
    let use_depc = il.new_label();
    let use_epc = il.new_label();
    let user = il.new_label();
    let kernel = il.new_label();

    let ps = il.reg(4, reg("ps")?);
    let four = il.const_(4, 4);
    let bit = il.test_bit(4, ps, four);
    il.append(il.if_expr(bit, double, normal));
    il.mark_label(double);
    let ndepc = il.reg(1, reg("config_ndepc")?);
    let zero = il.const_(1, 0);
    let present = il.compare_not_equal(1, ndepc, zero);
    il.append(il.if_expr(present, use_depc, use_epc));
    for (label, register) in [(use_depc, "depc"), (use_epc, "epc1")] {
        il.mark_label(label);
        let pc = il.const_pointer(4, address as i64);
        il.append(il.set_reg(4, reg(register)?, pc));
        finish(il, cause, "doubleexception")?;
    }
    il.mark_label(normal);
    let pc = il.const_pointer(4, address as i64);
    il.append(il.set_reg(4, reg("epc1")?, pc));
    let ps = il.reg(4, reg("ps")?);
    let five = il.const_(4, 5);
    let bit = il.test_bit(4, ps, five);
    il.append(il.if_expr(bit, user, kernel));
    let pairs: [(Label, &str); 2] = [(user, "userexception"), (kernel, "kernelexception")];
    for (label, vector) in pairs {
        il.mark_label(label);
        finish(il, cause, vector)?;
    }
    Ok(())
}

/// `finish(il, cause, vector)`.
fn finish(il: &Il, cause: i64, vector: &str) -> Result<(), Raise> {
    let c = il.const_(1, cause);
    il.append(il.set_reg(1, reg("exccause")?, c));
    let ps = il.reg(4, reg("ps")?);
    let sixteen = il.const_(4, 16);
    let v = il.or_expr(4, ps, sixteen);
    il.append(il.set_reg(4, reg("ps")?, v));
    let target = il.reg(4, reg(vector)?);
    il.append(il.jump(target));
    Ok(())
}

/// `double_return(il)`.
pub fn double_return(il: &Il) -> Result<(), Raise> {
    let present = il.new_label();
    let absent = il.new_label();
    let ndepc = il.reg(1, reg("config_ndepc")?);
    let zero = il.const_(1, 0);
    let cond = il.compare_not_equal(1, ndepc, zero);
    il.append(il.if_expr(cond, present, absent));
    il.mark_label(present);
    let depc = il.reg(4, reg("depc")?);
    il.append(il.ret(depc));
    il.mark_label(absent);
    let epc1 = il.reg(4, reg("epc1")?);
    il.append(il.ret(epc1));
    Ok(())
}
