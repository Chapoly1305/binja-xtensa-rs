//! Dispatcher tables and the helpers the reference shares between lift
//! functions: `_reg_name`, `_lift_cond`, `_lift_cmov`, `maximum_window_group`
//! (ar_operands.py), and `_lift_RER`/`_lift_WER`, which sit above the helpers
//! in `lifter.py`.

use std::sync::OnceLock;

use xtensa_isa::{Field, Insn, Opcode, OPCODE_COUNT};

use super::{tables, Lift, Raise};
use crate::il::{Il, R};
use crate::regs;

/// A lift function: `(insn, addr, il, data) -> insn.length`.
pub type Handler = fn(&Insn, u64, &Il, &[u8]) -> Lift;

/// The Python attribute named by a `_reg_name` format suffix.
pub fn field_of(name: &str) -> Field {
    match name {
        "r" => Field::R,
        "s" => Field::S,
        "t" => Field::T,
        "op1" => Field::Op1,
        "op2" => Field::Op2,
        "sr" => Field::Sr,
        "imm4" => Field::Imm4,
        "imm8" => Field::Imm8,
        "m" => Field::M,
        "n" => Field::N,
        other => panic!("unsupported _reg_name field {other}"),
    }
}

/// `_reg_name(insn, fmt, offset)`: `fmt` is `a`/`b`/`f`/`epc` followed by a
/// field name (`"as"`, `"bt"`, `"fr"`, `"epcimm4"`, ...).
pub fn reg_name(insn: &Insn, fmt: &str, offset: i64) -> Result<R, Raise> {
    let (prefix, field) = if let Some(rest) = fmt.strip_prefix("epc") {
        ("epc", rest)
    } else {
        fmt.split_at(1)
    };
    let value = insn
        .field(field_of(field))
        .ok_or(Raise::Other("_reg_name: Could not find property"))?;
    regs::numbered(prefix, value as i64 + offset)
}

/// Shorthand for `_reg_name(insn, fmt)` with no offset.
pub fn rn(insn: &Insn, fmt: &str) -> Result<R, Raise> {
    reg_name(insn, fmt, 0)
}

/// `insn.target_offset(addr)`; `None` in Python reaches ctypes as an error.
pub fn target(insn: &Insn, addr: u64) -> Result<i64, Raise> {
    insn.target_offset(addr as u32).ok_or(Raise::Other("target_offset returned None"))
}

/// `_lift_cond(cond, insn, addr, il)` on the per-instruction path (no
/// conditional handler installed; the loop workflow installs one and is
/// ported separately).
pub fn lift_cond(cond: u64, insn: &Insn, addr: u64, il: &Il) -> Lift {
    let tgt = target(insn, addr)?;
    let next = addr as i64 + insn.len as i64;
    let mut true_label = il.get_label_for_address(tgt as u64);
    let mut false_label = il.get_label_for_address(next as u64);
    let must_mark_true = true_label.is_none();
    let t = *true_label.get_or_insert_with(|| il.new_label());
    let must_mark_false = false_label.is_none();
    let f = *false_label.get_or_insert_with(|| il.new_label());
    il.append(il.if_expr(cond, t, f));
    if must_mark_true {
        il.mark_label(t);
        il.append(il.jump(il.const_(4, tgt)));
    }
    if must_mark_false {
        il.mark_label(f);
        il.append(il.jump(il.const_(4, next)));
    }
    Ok(insn.len as usize)
}

/// `_lift_cmov(cond, insn, addr, il, float)`.
pub fn lift_cmov(cond: u64, insn: &Insn, il: &Il, float: bool) -> Lift {
    let true_label = il.new_label();
    let false_label = il.new_label();
    il.append(il.if_expr(cond, true_label, false_label));
    il.mark_label(true_label);
    if float {
        let src = il.reg(4, rn(insn, "fs")?);
        il.append(il.set_reg(4, rn(insn, "fr")?, src));
    } else {
        let src = il.reg(4, rn(insn, "as")?);
        il.append(il.set_reg(4, rn(insn, "ar")?, src));
    }
    il.mark_label(false_label);
    Ok(insn.len as usize)
}

/// `maximum_window_group(insn)` from ar_operands.py.
pub fn maximum_window_group(insn: &Insn) -> Result<i64, Raise> {
    let name = insn.mnemonic().replace('.', "_");
    if tables::SPECIAL_WINDOW_RULES.contains(&name.as_str()) {
        return Ok(0);
    }
    let fields = tables::ar_fields(&name).ok_or(Raise::MissingArMetadata)?;
    let mut max = 0i64;
    for f in fields.chars() {
        // getattr(insn, field) is None -> max() raises TypeError.
        let v = insn
            .field(field_of(&f.to_string()))
            .ok_or(Raise::Other("maximum_window_group: None operand"))?;
        max = max.max(v as i64);
    }
    for &v in tables::implicit_ar(&name) {
        max = max.max(v);
    }
    Ok(max >> 2)
}

/// `_lift_RER`.
pub fn lift_rer(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let src = il.reg(4, rn(insn, "as")?);
    let out = rn(insn, "at")?;
    let intr = regs::intrinsic("read_external_register")?;
    il.append(il.intrinsic(&[out], intr, &[src]));
    Ok(insn.len as usize)
}

/// `_lift_WER`.
pub fn lift_wer(insn: &Insn, _addr: u64, il: &Il, _data: &[u8]) -> Lift {
    let a = il.reg(4, rn(insn, "as")?);
    let b = il.reg(4, rn(insn, "at")?);
    let intr = regs::intrinsic("write_external_register")?;
    il.append(il.intrinsic(&[], intr, &[a, b]));
    Ok(insn.len as usize)
}

fn common_handler(name: &str) -> Option<Handler> {
    Some(match name {
        "RER" => lift_rer,
        "WER" => lift_wer,
        _ => return None,
    })
}

/// The Python `globals()["_lift_" + name]` lookup, as a per-opcode table.
fn table() -> &'static [Option<Handler>; OPCODE_COUNT] {
    static TABLE: OnceLock<[Option<Handler>; OPCODE_COUNT]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [None; OPCODE_COUNT];
        for &op in Opcode::ALL {
            t[op as usize] = by_name(&op.mnemonic().replace('.', "_"));
        }
        t
    })
}

/// Resolve a Python handler name to its port. Exactly one module answers
/// for each name in `tables::LIFT_HANDLER_NAMES`.
pub fn by_name(name: &str) -> Option<Handler> {
    common_handler(name)
        .or_else(|| super::core::handler(name))
        .or_else(|| super::window::handler(name))
        .or_else(|| super::fp_mac::handler(name))
}

/// The reference dispatcher's choice of function for `insn`.
pub fn handler_for(insn: &Insn) -> Option<Handler> {
    if insn.mac_kind().is_some() {
        return Some(super::fp_mac::lift_mac_arithmetic);
    }
    table()[insn.opcode as usize]
}
