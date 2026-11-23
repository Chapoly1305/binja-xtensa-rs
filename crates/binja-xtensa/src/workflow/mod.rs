//! The reference plugin's function workflow (`loop_workflow.py`) and the
//! settings it reads (`vector_profile.py`), registered through the raw core
//! API.
//!
//! The reference clones `core.function.metaAnalysis` into
//! `matteroverwatch.xtensa.loops`, registers three action activities and
//! inserts them after `core.function.generateLiftedIL` in the order
//! loop ends, shared window tails, vector profile. Selecting that workflow
//! with `analysis.workflows.functionWorkflow` runs them on every function's
//! lifted IL. This module registers the same workflow, activities (same
//! configuration JSON, byte for byte) and settings, so existing analysis
//! options keep working when this plugin replaces the Python one.
//!
//! Activities are created with `BNCreateActivity` rather than the Rust
//! wrapper because the transforms need the raw `BNAnalysisContext*` and the
//! raw lifted-IL `BNLowLevelILFunction*` (the builder in [`crate::il`] and the
//! readers in [`crate::il_read`] work on raw handles).

pub mod loops;
pub mod tail;
pub mod vector;

use std::ffi::{c_char, c_void, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::OnceLock;

use binaryninjacore_sys::*;

use crate::il_read::{CopyUnsupported, FunctionRef, Llil, SettingsRef, ViewRef};
use crate::lift::Raise;

/// `loop_workflow.NAME`.
pub const WORKFLOW_NAME: &str = "matteroverwatch.xtensa.loops";
const BASE_WORKFLOW: &str = "core.function.metaAnalysis";
const INSERT_AFTER: &str = "core.function.generateLiftedIL";

pub const LOOP_ACTIVITY: &str = "matteroverwatch.xtensa.loopEnds";
pub const VECTOR_ACTIVITY: &str = "matteroverwatch.xtensa.vectorProfile";
pub const TAIL_ACTIVITY: &str = "matteroverwatch.xtensa.sharedWindowTail";

/// `json.dumps(...)` of the reference activity configurations (default
/// separators, insertion order).
const LOOP_CONFIG: &str = r#"{"name": "matteroverwatch.xtensa.loopEnds", "title": "Xtensa hardware loops", "description": "Insert hardware loop-end control flow into lifted IL.", "role": "action", "eligibility": {"auto": {}}}"#;
const VECTOR_CONFIG: &str = r#"{"name": "matteroverwatch.xtensa.vectorProfile", "title": "Xtensa window vectors", "description": "Bind explicitly selected vector layout to runtime VECBASE.", "role": "action", "eligibility": {"auto": {}}}"#;
const TAIL_CONFIG: &str = r#"{"name": "matteroverwatch.xtensa.sharedWindowTail", "title": "Share window overflow tails", "description": "Share identical terminal window-bank overflow transitions after preserving the fault PC.", "role": "action", "eligibility": {"auto": {}}}"#;

/// `vector_profile.KEY` / `DEPC_KEY` and their schemas.
pub const VECTOR_KEY: &str = "arch.xtensa.windowVectorProfile";
pub const DEPC_KEY: &str = "arch.xtensa.depcPresence";
const VECTOR_SCHEMA: &str = r#"{"title": "Xtensa window vector layout", "description": "Explicit ESP32/S3 layout relative to runtime VECBASE; generic leaves vectors unresolved.", "type": "string", "default": "generic", "enum": ["generic", "esp32-esp32s3"]}"#;
const DEPC_SCHEMA: &str = r#"{"title": "Xtensa DEPC configuration", "description": "Explicit optional DEPC presence; unknown preserves both architectural paths.", "type": "string", "default": "unknown", "enum": ["unknown", "present", "absent"]}"#;

/// The module-level `settings = Settings()` of `vector_profile.py`.
static SETTINGS: OnceLock<SettingsRef> = OnceLock::new();

pub(crate) fn settings() -> Option<&'static SettingsRef> {
    SETTINGS.get()
}

fn cstr(s: &str) -> CString {
    CString::new(s).expect("no NUL in workflow strings")
}

/// What importing `vector_profile` does: register the `arch` group and both
/// settings on the default settings instance, which the transform then reads.
fn register_settings() {
    let Some(settings) = SettingsRef::new("default") else { return };
    settings.register_group("arch", "Architecture");
    settings.register_setting(VECTOR_KEY, VECTOR_SCHEMA);
    settings.register_setting(DEPC_KEY, DEPC_SCHEMA);
    let _ = SETTINGS.set(settings);
}

/// Why a transform stopped early. The reference transforms raise; Binary
/// Ninja's activity wrapper logs the exception and the lifted IL stays as it
/// was (a destination function built so far is dropped, never installed).
#[derive(Debug)]
pub enum Abort {
    Raise(Raise),
    Copy(CopyUnsupported),
    Other(&'static str),
}

impl From<Raise> for Abort {
    fn from(r: Raise) -> Self {
        Abort::Raise(r)
    }
}

impl From<CopyUnsupported> for Abort {
    fn from(c: CopyUnsupported) -> Self {
        Abort::Copy(c)
    }
}

/// The `AnalysisContext` of one activity invocation.
pub struct Context {
    raw: *mut BNAnalysisContext,
}

impl Context {
    /// `context.lifted_il`.
    pub fn lifted_il(&self) -> Option<Llil> {
        // SAFETY: the context is live for the action; the getter returns a
        // new reference (or null), which `Llil` takes over.
        unsafe { Llil::from_owned(BNAnalysisContextGetLiftedILFunction(self.raw)) }
    }

    /// `context.lifted_il = il`.
    pub fn set_lifted_il(&self, il: &Llil) {
        // SAFETY: both handles live; the core takes its own reference.
        unsafe { BNSetLiftedILFunction(self.raw, il.raw()) }
    }

    /// `context.function`.
    pub fn function(&self) -> Option<FunctionRef> {
        // SAFETY: live context; the getter returns a new reference or null.
        unsafe { FunctionRef::from_owned(BNAnalysisContextGetFunction(self.raw)) }
    }

    /// `context.view`.
    pub fn view(&self) -> Option<ViewRef> {
        // SAFETY: live context; the getter returns a new reference or null.
        unsafe { ViewRef::from_owned(BNAnalysisContextGetBinaryView(self.raw)) }
    }
}

/// `function.arch.name != 'xtensa'`.
pub(crate) fn is_xtensa(function: &FunctionRef) -> bool {
    function.arch().name() == "xtensa"
}

/// `Activity._action`: run the transform, swallow what it raises.
fn run(ac: *mut BNAnalysisContext, transform: fn(&Context) -> Result<(), Abort>) {
    if ac.is_null() {
        return;
    }
    let ctx = Context { raw: ac };
    // A panic must not unwind into the core; treat it like a raise.
    let _ = catch_unwind(AssertUnwindSafe(|| transform(&ctx)));
}

extern "C" fn loop_action(_ctxt: *mut c_void, ac: *mut BNAnalysisContext) {
    run(ac, loops::transform)
}
extern "C" fn vector_action(_ctxt: *mut c_void, ac: *mut BNAnalysisContext) {
    run(ac, vector::transform)
}
extern "C" fn tail_action(_ctxt: *mut c_void, ac: *mut BNAnalysisContext) {
    run(ac, tail::transform)
}

type Action = extern "C" fn(*mut c_void, *mut BNAnalysisContext);

/// `loop_workflow.register()`, preceded by the settings registration done
/// when `vector_profile` is imported. Returns whether the workflow was
/// registered (the reference's `assert workflow.insert_after(...)`).
pub fn register() -> bool {
    register_settings();
    let base_name = cstr(BASE_WORKFLOW);
    let name = cstr(WORKFLOW_NAME);
    let empty = cstr("");
    // SAFETY: core workflow API calls with valid C strings and handles
    // returned by the core; each activity and the base workflow reference
    // are released once registered, as the Python objects are collected. The
    // cloned workflow stays referenced, like the module-level `workflow`.
    unsafe {
        let base = BNWorkflowGetOrCreate(base_name.as_ptr());
        if base.is_null() {
            return false;
        }
        let workflow = BNWorkflowClone(base, name.as_ptr(), empty.as_ptr());
        BNFreeWorkflow(base);
        if workflow.is_null() {
            return false;
        }
        let activities: [(&str, Action); 3] =
            [(LOOP_CONFIG, loop_action), (VECTOR_CONFIG, vector_action), (TAIL_CONFIG, tail_action)];
        for (config, action) in activities {
            let config = cstr(config);
            let activity = BNCreateActivity(config.as_ptr(), ptr::null_mut(), Some(action));
            if activity.is_null() {
                return false;
            }
            let mut no_subactivities: [*const c_char; 0] = [];
            let registered =
                BNWorkflowRegisterActivity(workflow, activity, no_subactivities.as_mut_ptr(), 0);
            if !registered.is_null() {
                BNFreeActivity(registered);
            }
            BNFreeActivity(activity);
        }
        let names = [cstr(LOOP_ACTIVITY), cstr(TAIL_ACTIVITY), cstr(VECTOR_ACTIVITY)];
        let mut list: Vec<*const c_char> = names.iter().map(|n| n.as_ptr()).collect();
        let after = cstr(INSERT_AFTER);
        if !BNWorkflowInsertAfter(workflow, after.as_ptr(), list.as_mut_ptr(), list.len()) {
            return false;
        }
        BNRegisterWorkflow(workflow, empty.as_ptr())
    }
}
