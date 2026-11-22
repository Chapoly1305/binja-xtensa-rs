//! Per-instruction lifting, ported function by function from the reference
//! `lifter.py` and its helper modules.
//!
//! Porting rules (see `PORTING.md`):
//! * One Rust function per Python `_lift_*` function, same name in snake case,
//!   same order of `il` calls. Where Python defines a name twice, the later
//!   definition wins (module globals), so port the later one.
//! * A Python exception becomes `Err(Raise::..)`: the callback then fails and
//!   the IL appended so far stays, exactly as with the reference.
//! * A Python lift function that returns `insn.length` returns `Ok(len)`.

pub mod common;
pub mod tables;
pub mod core;
pub mod fp_mac;
pub mod window;

use xtensa_isa::Insn;

use crate::il::Il;
use crate::info::decoded;

/// A Python exception escaping the reference lift callback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Raise {
    /// `get_reg_index` on a name the architecture does not define.
    NoSuchRegister,
    /// `get_intrinsic_index` on an unknown name.
    NoSuchIntrinsic,
    /// `maximum_window_group`: mnemonic missing from `AR_FIELDS`.
    MissingArMetadata,
    /// Any other exception or failed assertion in the reference; the payload
    /// names the Python site for reviewers.
    Other(&'static str),
    /// The reference lift function returned `None` (the callback reports failure).
    ReturnedNone,
}

pub type Lift = Result<usize, Raise>;

/// What the reference `lift()` dispatcher does.
fn lift(insn: &Insn, addr: u64, il: &Il, data: &[u8]) -> Lift {
    let Some(handler) = common::handler_for(insn) else {
        il.append(il.unimplemented());
        return Ok(insn.len as usize);
    };
    let group = common::maximum_window_group(insn)?;
    if group != 0 {
        let g = il.const_(4, group);
        window::window_check(il, g, addr)?;
    }
    handler(insn, addr, il, data)
}

/// The `getInstructionLowLevelIL` callback body.
pub fn instruction_llil(data: &[u8], addr: u64, il: &Il) -> Option<usize> {
    let insn = decoded(data)?;
    lift(&insn, addr, il, data).ok()
}
