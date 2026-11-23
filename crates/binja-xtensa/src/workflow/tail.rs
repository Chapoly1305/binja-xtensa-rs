//! Port of `window_tail_workflow.transform`: share the identical terminal
//! window-overflow transition that `window_check` generates after each
//! faulting site's own PS/EPC1 update.

use std::collections::{HashMap, HashSet};

use binaryninjacore_sys::BNLowLevelILOperation::{LLIL_CONST_PTR, LLIL_JUMP, LLIL_REG, LLIL_SET_REG};

use super::{is_xtensa, Abort, Context};
use crate::ffi_arch;
use crate::il::{temp, Il};
use crate::il_read::{copy_expr_to, Block, Llil};
use crate::lift::window::{rotate_bank, window_bit};
use crate::regs;

/// `str(ILRegister)`: `tempN` for temporaries, else the architecture's name.
fn reg_name(id: u64) -> String {
    let id = id as u32;
    if id & 0x8000_0000 != 0 {
        format!("temp{}", id & 0x7fff_ffff)
    } else {
        ffi_arch::register_name(id).to_owned()
    }
}

const OVERFLOW_VECTORS: [&str; 3] = ["windowoverflow4", "windowoverflow8", "windowoverflow12"];

/// `_discarded_tail_blocks(source, blocks, sites)`: block starts of closed
/// generated overflow regions.
fn discarded_tail_blocks(source: &Llil, blocks: &[Block], sites: &HashSet<usize>) -> HashSet<usize> {
    let by_start: HashMap<usize, usize> = blocks.iter().enumerate().map(|(i, b)| (b.start, i)).collect();
    let mut discarded = HashSet::new();
    for cut in blocks {
        let Some(first) = (cut.start..cut.end).filter(|i| sites.contains(i)).min() else { continue };
        let address = source.instr(first).address;
        let mut region: HashMap<usize, usize> = HashMap::new();
        let mut pending: Vec<usize> = cut.outgoing();
        let mut valid = true;
        while let Some(start) = pending.pop() {
            if region.contains_key(&start) {
                continue;
            }
            if start == cut.start {
                valid = false;
                break;
            }
            let Some(&bi) = by_start.get(&start) else {
                valid = false;
                break;
            };
            region.insert(start, bi);
            let block = &blocks[bi];
            if (block.start..block.end).any(|i| source.instr(i).address != address) {
                valid = false;
                break;
            }
            let edges = block.outgoing();
            if !edges.is_empty() {
                pending.extend(edges);
            } else {
                let last = source.instr(block.end - 1);
                let ok = last.op == LLIL_JUMP && {
                    let dest = source.expr(last.operands[0] as usize);
                    dest.op == LLIL_REG && OVERFLOW_VECTORS.contains(&reg_name(dest.operands[0]).as_str())
                };
                if !ok {
                    valid = false;
                    break;
                }
            }
        }
        if valid
            && region.values().all(|&bi| {
                blocks[bi].incoming().iter().all(|s| region.contains_key(s) || *s == cut.start)
            })
        {
            discarded.extend(region.keys().copied());
        }
    }
    discarded
}

pub fn transform(ctx: &Context) -> Result<(), Abort> {
    let Some(source) = ctx.lifted_il() else { return Ok(()) };
    let function = ctx.function().ok_or(Abort::Other("context.function is None"))?;
    if !is_xtensa(&function) {
        return Ok(());
    }
    let arch = function.arch();
    let mut sites: HashSet<usize> = HashSet::new();
    let blocks = source.blocks();
    for block in &blocks {
        for i in block.start..block.end.saturating_sub(1).max(block.start) {
            let epc = source.instr(i);
            if epc.op != LLIL_SET_REG || reg_name(epc.operands[0]) != "epc1" {
                continue;
            }
            let nxt = source.instr(i + 1);
            if source.expr(epc.operands[1] as usize).op == LLIL_CONST_PTR
                && nxt.op == LLIL_SET_REG
                && reg_name(nxt.operands[0]) == "temp24"
                && nxt.size == 4
                && source
                    .expr_text(arch, nxt.operands[1] as usize)
                    .ok_or(Abort::Other("BNGetLowLevelILExprText returned False"))?
                    == "(windowbase + temp25.d) & 0xf"
            {
                sites.insert(i);
            }
        }
    }
    if sites.len() < 2 {
        return Ok(());
    }
    let discarded = discarded_tail_blocks(&source, &blocks, &sites);
    let dest = Llil::create(arch, &function).ok_or(Abort::Other("LowLevelILFunction creation failed"))?;
    dest.prepare_to_copy_function(&source);
    // SAFETY: `dest` is a live LLIL function owned for this whole scope, and
    // `arch` is its architecture.
    let il = unsafe { Il::from_raw(dest.raw(), arch.raw()) };
    let shared = il.new_label();
    for block in &blocks {
        if discarded.contains(&block.start) {
            continue;
        }
        dest.prepare_to_copy_block(block);
        for i in block.start..block.end {
            let ins = source.instr(i);
            il.set_current_address_arch(ins.address, block.arch);
            il.append(copy_expr_to(&source, &ins, &il)?);
            if sites.contains(&i) {
                il.append(il.goto(shared));
                break;
            }
        }
    }
    let first = *sites.iter().min().expect("at least two sites");
    il.set_current_address_arch(source.instr(first).address, arch);
    il.mark_label(shared);
    let wb = il.reg(4, regs::reg("windowbase")?);
    let t25 = il.reg(4, temp(25));
    let new_window = il.add(4, wb, t25);
    rotate_bank(&il, new_window)?;
    for (offset, vector) in [(1, 4), (2, 8)] {
        let (hit, onward) = (il.new_label(), il.new_label());
        let bit = window_bit(&il, offset)?;
        il.append(il.if_expr(bit, hit, onward));
        il.mark_label(hit);
        let target = il.reg(4, regs::reg(&format!("windowoverflow{vector}"))?);
        il.append(il.jump(target));
        il.mark_label(onward);
    }
    let target = il.reg(4, regs::reg("windowoverflow12")?);
    il.append(il.jump(target));
    il.finalize();
    ctx.set_lifted_il(&dest);
    Ok(())
}
