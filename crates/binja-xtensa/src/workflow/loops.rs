//! Port of `loop_workflow.transform`: hardware loop-end control flow.
//!
//! The reference decodes every instruction address of the lifted IL, finds
//! the fallthrough instructions that end a `LOOP*` body (or, when the
//! function writes LBEG/LEND/LCOUNT, every fallthrough instruction), and
//! rebuilds the function: those instructions are lifted again into the new
//! IL followed by a loop-end check, everything else is copied.
//!
//! Python dicts keep insertion order and that order is observable (the label
//! map of the dynamic `jump_to`), so the maps here are insertion-ordered
//! vectors with an index.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use binaryninjacore_sys::BNBranchType;
use xtensa_isa::{decode, Insn};

use super::{is_xtensa, Abort, Context};
use crate::il::{CondHandler, Il, Label, E};
use crate::il_read::{copy_expr_to, Llil};
use crate::info::instruction_info;
use crate::lift::{self, Lift, Raise};
use crate::regs;

/// Reserved synthetic address of the shared window-overflow block.
const SHARED_OVERFLOW_ADDRESS: u64 = 0x1_0000_0000;

/// An insertion-ordered map (a Python dict restricted to what is used here).
struct Ordered<V> {
    items: Vec<(u64, V)>,
    index: HashMap<u64, usize>,
}

impl<V> Ordered<V> {
    fn new() -> Self {
        Ordered { items: Vec::new(), index: HashMap::new() }
    }
    fn get(&self, key: u64) -> Option<&V> {
        self.index.get(&key).map(|&i| &self.items[i].1)
    }
    fn contains(&self, key: u64) -> bool {
        self.index.contains_key(&key)
    }
    /// `d[key] = value`.
    fn set(&mut self, key: u64, value: V) {
        match self.index.get(&key) {
            Some(&i) => self.items[i].1 = value,
            None => {
                self.index.insert(key, self.items.len());
                self.items.push((key, value));
            }
        }
    }
    fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// What `transfer` and `emit_check` close over.
struct State {
    /// `targets = {address: LowLevelILLabel() for address in machine}`.
    targets: Ordered<Label>,
    /// `endpoints[address] = (begin, end)`; `begin` is `None` when dynamic.
    endpoints: Ordered<(Option<u64>, u64)>,
}

impl State {
    /// `transfer(address)`.
    fn transfer(&self, il: &Il, address: i64) -> E {
        let label = if address >= 0 { self.targets.get(address as u64) } else { None };
        match label {
            Some(&label) => il.goto(label),
            None => {
                let c = il.const_pointer(4, address);
                il.jump(c)
            }
        }
    }

    /// `emit_check(address)`.
    fn emit_check(&self, il: &Il, address: u64) -> Result<(), Raise> {
        let &(begin, end) = self.endpoints.get(address).ok_or(Raise::Other("emit_check: KeyError"))?;
        let (repeat, done) = (il.new_label(), il.new_label());
        let lend = il.reg(4, regs::reg("lend")?);
        let c_end = il.const_(4, end as i64);
        let mut active = il.compare_equal(4, lend, c_end);
        if let Some(begin) = begin {
            let lbeg = il.reg(4, regs::reg("lbeg")?);
            let c_begin = il.const_(4, begin as i64);
            let eq = il.compare_equal(4, lbeg, c_begin);
            active = il.and_expr(1, active, eq);
        }
        let ps = il.reg(4, regs::reg("ps")?);
        let c16 = il.const_(4, 16);
        let masked = il.and_expr(4, ps, c16);
        let c0 = il.const_(4, 0);
        let enabled = il.compare_equal(4, masked, c0);
        let both = il.and_expr(1, active, enabled);
        let lcount = il.reg(4, regs::reg("lcount")?);
        let c0 = il.const_(4, 0);
        let nonzero = il.compare_not_equal(4, lcount, c0);
        let condition = il.and_expr(1, both, nonzero);
        il.append(il.if_expr(condition, repeat, done));
        il.mark_label(repeat);
        let lcount = il.reg(4, regs::reg("lcount")?);
        let c1 = il.const_(4, 1);
        let dec = il.sub(4, lcount, c1);
        il.append(il.set_reg(4, regs::reg("lcount")?, dec));
        match begin {
            None => {
                let lbeg = il.reg(4, regs::reg("lbeg")?);
                let targets: Vec<(u64, Label)> = self.targets.items.clone();
                il.append(il.jump_to(lbeg, &targets));
            }
            Some(begin) => {
                let &label = self.targets.get(begin).ok_or(Raise::Other("targets[begin]: KeyError"))?;
                il.append(il.goto(label));
            }
        }
        il.mark_label(done);
        Ok(())
    }
}

/// The `conditional(cond, decoded, pc, il)` closure installed as
/// `_xtensa_conditional_handler` while an endpoint is re-lifted.
fn conditional(state: &State, cond: E, decoded: &Insn, pc: u64, il: &Il) -> Lift {
    let (taken, fallthrough) = (il.new_label(), il.new_label());
    il.append(il.if_expr(cond, taken, fallthrough));
    il.mark_label(taken);
    // `transfer(None)` reaches ctypes and raises.
    let target = decoded.target_offset(pc as u32).ok_or(Raise::Other("transfer(None)"))?;
    il.append(state.transfer(il, target));
    il.mark_label(fallthrough);
    state.emit_check(il, pc)?;
    il.append(state.transfer(il, pc as i64 + decoded.len as i64));
    Ok(decoded.len as usize)
}

pub fn transform(ctx: &Context) -> Result<(), Abort> {
    let Some(source) = ctx.lifted_il() else { return Ok(()) };
    let function = ctx.function().ok_or(Abort::Other("context.function is None"))?;
    let view = ctx.view().ok_or(Abort::Other("context.view is None"))?;
    if !is_xtensa(&function) {
        return Ok(());
    }
    let arch = function.arch();

    // machine = {address: Instruction.decode(view.read(address, 3))}, in
    // `source.instructions` order (blocks, then indices).
    let mut machine: Ordered<Insn> = Ordered::new();
    for block in source.blocks() {
        for i in block.start..block.end {
            let address = source.instr(i).address;
            if !machine.contains(address) {
                if let Ok(insn) = decode(&view.read(address, 3)) {
                    machine.set(address, insn);
                }
            }
        }
    }
    let mut loops: Vec<(u64, u64)> = Vec::new();
    for (addr, insn) in &machine.items {
        if matches!(insn.mnemonic(), "LOOP" | "LOOPNEZ" | "LOOPGTZ") {
            let imm8 = insn.imm8().ok_or(Raise::Other("LOOP without imm8"))?;
            loops.push((addr + insn.len as u64, addr + 4 + imm8 as u64));
        }
    }
    let dynamic = machine
        .items
        .iter()
        .any(|(_, insn)| matches!(insn.mnemonic(), "WSR" | "XSR") && matches!(insn.sr(), Some(0..=2)));
    if loops.is_empty() && !dynamic {
        return Ok(());
    }

    let mut endpoints: Ordered<(Option<u64>, u64)> = Ordered::new();
    for (address, insn) in &machine.items {
        let address = *address;
        let info = instruction_info(&view.read(address, 3), address);
        let fallthrough = info.is_some_and(|info| {
            info.count == 0 || info.kinds[..info.count].contains(&BNBranchType::FalseBranch)
        });
        if !fallthrough {
            continue;
        }
        let next = address + insn.len as u64;
        if dynamic {
            endpoints.set(address, (None, next));
        } else {
            for &(begin, end) in &loops {
                if next == end {
                    endpoints.set(address, (Some(begin), end));
                }
            }
        }
    }
    if endpoints.is_empty() {
        return Ok(());
    }

    // The shared window-overflow tail may be owned by an instruction that is
    // re-lifted below while other sites still jump to it: keep its whole
    // region as copied IL.
    let mut shared_tail_indices: HashSet<usize> = HashSet::new();
    if let Some((true, tail)) = source.label_for_address(arch, SHARED_OVERFLOW_ADDRESS) {
        let blocks = source.blocks();
        let by_start: HashMap<usize, usize> = blocks.iter().enumerate().map(|(i, b)| (b.start, i)).collect();
        let mut pending: Vec<usize> =
            (0..blocks.len()).filter(|&i| blocks[i].start <= tail && tail < blocks[i].end).collect();
        let mut visited: HashSet<usize> = HashSet::new();
        while let Some(bi) = pending.pop() {
            let block = &blocks[bi];
            if !visited.insert(block.start) {
                continue;
            }
            let from = if block.start <= tail && tail < block.end { block.start.max(tail) } else { block.start };
            shared_tail_indices.extend(from..block.end);
            pending.extend(block.outgoing().into_iter().filter_map(|s| by_start.get(&s).copied()));
        }
    }

    let dest = Llil::create(arch, &function).ok_or(Abort::Other("LowLevelILFunction creation failed"))?;
    dest.prepare_to_copy_function(&source);
    // SAFETY: `dest` is a live LLIL function owned for this whole scope, and
    // `arch` is its architecture.
    let il = unsafe { Il::from_raw(dest.raw(), arch.raw()) };
    let mut targets: Ordered<Label> = Ordered::new();
    for (address, _) in &machine.items {
        targets.set(*address, il.new_label());
    }
    let state = Rc::new(State { targets, endpoints });
    let mut marked: HashSet<u64> = HashSet::new();
    let mut relifted: HashSet<u64> = HashSet::new();

    for block in source.blocks() {
        dest.prepare_to_copy_block(&block);
        for index in block.start..block.end {
            let instruction = source.instr(index);
            let address = instruction.address;
            il.set_current_address_arch(address, block.arch);
            if let Some(&label) = state.targets.get(address) {
                if marked.insert(address) {
                    il.mark_label(label);
                }
            }
            if shared_tail_indices.contains(&index) {
                il.append(copy_expr_to(&source, &instruction, &il)?);
                continue;
            }
            if state.endpoints.contains(address) {
                if !relifted.contains(&address) {
                    let insn = *machine.get(address).ok_or(Abort::Other("machine[address]: KeyError"))?;
                    let handler_state = Rc::clone(&state);
                    let handler: CondHandler =
                        Rc::new(move |cond, decoded, pc, il| conditional(&handler_state, cond, decoded, pc, il));
                    il.set_conditional_handler(Some(handler));
                    let data = view.read(address, 3);
                    let result = relift(&state, &insn, address, &il, &data);
                    il.set_conditional_handler(None);
                    result?;
                    relifted.insert(address);
                }
                continue;
            }
            il.append(copy_expr_to(&source, &instruction, &il)?);
        }
    }
    il.finalize();
    ctx.set_lifted_il(&dest);
    Ok(())
}

/// The body of the reference's `try:` block around the re-lift.
fn relift(state: &State, insn: &Insn, address: u64, il: &Il, data: &[u8]) -> Result<(), Raise> {
    match lift::lift(insn, address, il, data) {
        // The return value is ignored; returning None is not an exception.
        Ok(_) | Err(Raise::ReturnedNone) => {}
        Err(e) => return Err(e),
    }
    if !insn.mnemonic().starts_with('B') {
        state.emit_check(il, address)?;
        il.append(state.transfer(il, (address + insn.len as u64) as i64));
    }
    Ok(())
}
