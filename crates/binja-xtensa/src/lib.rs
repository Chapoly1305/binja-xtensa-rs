//! Native Xtensa architecture plugin for Binary Ninja.
//!
//! Decoding and disassembly live in the dependency-free `xtensa-isa` crate.
//! This crate registers the architecture with the core (`ffi_arch`), answers
//! instruction info/text queries, and lifts to LLIL (`lift`) through a raw IL
//! builder (`il`) that mirrors the Python API the reference plugin used.
//! The reference's function workflow (hardware loops, shared window tails,
//! vector binding) is in `workflow`, reading lifted IL through `il_read`.

pub mod cc;
pub mod ffi_arch;
pub mod il;
pub mod il_read;
pub mod info;
pub mod lift;
pub mod model;
pub mod regs;
pub mod text;
pub mod workflow;

use binaryninja::architecture::{ArchitectureExt, CoreArchitecture};
use binaryninja::binary_view::BinaryViewType;
use binaryninja::Endianness;

/// `EM_XTENSA`.
const ELF_MACHINE_XTENSA: u32 = 94;

/// Registered architecture name. `xtensa` by default; the differential
/// harness loads this plugin next to the reference one under another name.
pub fn arch_name() -> String {
    std::env::var("XTENSA_RS_ARCH_NAME").unwrap_or_else(|_| "xtensa".to_owned())
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    let name = arch_name();
    let raw = ffi_arch::register(&name);
    if raw.is_null() {
        return false;
    }
    let arch = unsafe { CoreArchitecture::from_raw(raw) };
    let default = cc::register(&arch);
    if let Some(platform) = arch.standalone_platform() {
        platform.set_default_calling_convention(&default);
    }
    if name == "xtensa" {
        if let Some(elf) = BinaryViewType::by_name("ELF") {
            elf.register_arch(ELF_MACHINE_XTENSA, Endianness::LittleEndian, &arch);
        }
        // The function workflow and its settings have fixed names; register
        // them only when this plugin stands in for the reference, so a
        // side-by-side load (XTENSA_RS_ARCH_NAME) does not collide with it.
        workflow::register();
    }
    true
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginDependencies() {
    binaryninja::add_optional_plugin_dependency("view_elf");
}
