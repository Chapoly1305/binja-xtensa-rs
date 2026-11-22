//! Port of the reference lifter (see the module list in `lift/mod.rs`).

use super::common::Handler;

/// Python handler names (mnemonic with '.' replaced by '_') ported here.
pub fn handler(name: &str) -> Option<Handler> {
    let _ = name;
    None
}

/// `_lift_mac_arithmetic`.
pub fn lift_mac_arithmetic(insn: &xtensa_isa::Insn, addr: u64, il: &crate::il::Il, data: &[u8]) -> super::Lift {
    let _ = (insn, addr, il, data);
    Err(super::Raise::Other("_lift_mac_arithmetic not yet ported"))
}
