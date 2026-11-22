//! Port of the reference lifter (see the module list in `lift/mod.rs`).

use super::common::Handler;

/// Python handler names (mnemonic with '.' replaced by '_') ported here.
pub fn handler(name: &str) -> Option<Handler> {
    let _ = name;
    None
}

/// `window_check(il, maximum_group, address)` from window_exceptions.py.
pub fn window_check(il: &crate::il::Il, maximum_group: u64, address: u64) -> Result<(), super::Raise> {
    let _ = (il, maximum_group, address);
    Err(super::Raise::Other("window_check not yet ported"))
}
