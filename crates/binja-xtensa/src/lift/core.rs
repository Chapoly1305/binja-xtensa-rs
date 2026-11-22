//! Port of the reference lifter (see the module list in `lift/mod.rs`).

use super::common::Handler;

/// Python handler names (mnemonic with '.' replaced by '_') ported here.
pub fn handler(name: &str) -> Option<Handler> {
    let _ = name;
    None
}
