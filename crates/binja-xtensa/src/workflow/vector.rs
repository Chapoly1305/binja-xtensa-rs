//! Port of `vector_profile.transform`: bind the window/exception vector
//! registers to `vecbase + offset` and `config_ndepc` to a constant, in place,
//! according to the `arch.xtensa.windowVectorProfile` and
//! `arch.xtensa.depcPresence` settings of the view.

use binaryninjacore_sys::BNLowLevelILOperation::LLIL_REG;

use super::{is_xtensa, settings, Abort, Context, DEPC_KEY, VECTOR_KEY};
use crate::il::{Il, E};
use crate::regs;

/// `OFFSETS`, in dict order.
const OFFSETS: [(&str, i64); 9] = [
    ("windowoverflow4", 0),
    ("windowunderflow4", 64),
    ("windowoverflow8", 128),
    ("windowunderflow8", 192),
    ("windowoverflow12", 256),
    ("windowunderflow12", 320),
    ("kernelexception", 768),
    ("userexception", 832),
    ("doubleexception", 960),
];

pub fn transform(ctx: &Context) -> Result<(), Abort> {
    let Some(source) = ctx.lifted_il() else { return Ok(()) };
    let function = ctx.function().ok_or(Abort::Other("context.function is None"))?;
    if !is_xtensa(&function) {
        return Ok(());
    }
    let view = ctx.view().ok_or(Abort::Other("context.view is None"))?;
    let settings = settings().ok_or(Abort::Other("settings not registered"))?;
    let bind_vectors = view.setting_string(settings, VECTOR_KEY) == "esp32-esp32s3";
    let depc = view.setting_string(settings, DEPC_KEY);
    if !bind_vectors && depc == "unknown" {
        return Ok(());
    }
    // Expressions are only appended; snapshot the count first so the new
    // ones are not visited.
    let vectors: Vec<(u64, i64)> = if bind_vectors {
        let mut v = Vec::with_capacity(OFFSETS.len());
        for (name, offset) in OFFSETS {
            v.push((regs::reg(name)?.0 as u64, offset));
        }
        v
    } else {
        Vec::new()
    };
    let depc_index = if depc != "unknown" { Some(regs::reg("config_ndepc")?.0 as u64) } else { None };
    // SAFETY: `source` is a live LLIL function for this whole scope, lifted
    // for `function.arch`.
    let il = unsafe { Il::from_raw(source.raw(), function.arch().raw()) };
    let mut replacements: Vec<(usize, E)> = Vec::new();
    for index in 0..source.expr_count() {
        let expression = source.expr(index);
        if expression.op != LLIL_REG {
            continue;
        }
        let register = expression.operands[0];
        if Some(register) == depc_index {
            replacements.push((index, il.const_(1, if depc == "present" { 1 } else { 0 })));
        } else if let Some(&(_, offset)) = vectors.iter().find(|(r, _)| *r == register) {
            let vecbase = il.reg(4, regs::reg("vecbase")?);
            let c = il.const_(4, offset);
            replacements.push((index, il.add(4, vecbase, c)));
        }
    }
    for &(original, replacement) in &replacements {
        source.replace_expr(original, replacement);
    }
    if !replacements.is_empty() {
        il.finalize();
        ctx.set_lifted_il(&source);
    }
    Ok(())
}
