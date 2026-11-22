//! The `default` (CALL0-style) calling convention, mirroring the reference
//! plugin's declarative `XtensaCall0CallingConvention`.
//!
//! The reference defines no behaviour of its own, but being a Python class it
//! routed every core query (most often the incoming value of each register at
//! function entry) through the Python bridge. Here every answer is a table
//! lookup.

use binaryninja::architecture::{Architecture, RegisterId};
use binaryninja::calling_convention::{CallingConvention, CoreCallingConvention};
use binaryninja::function::Function;
use binaryninja::variable::{RegisterValue, RegisterValueType};

use crate::regs;
use crate::model::{self, cc};

fn ids(names: &[&str]) -> Vec<RegisterId> {
    names
        .iter()
        .map(|n| RegisterId(regs::reg(n).expect("model register").0))
        .collect()
}

pub struct Call0 {
    core: CoreCallingConvention,
    caller_saved: Vec<RegisterId>,
    int_args: Vec<RegisterId>,
    implicit: Vec<RegisterId>,
    ret: RegisterId,
    ret_hi: RegisterId,
}

impl Call0 {
    pub fn new(core: CoreCallingConvention) -> Self {
        Call0 {
            core,
            caller_saved: ids(cc::CALLER_SAVED_REGS),
            int_args: ids(cc::INT_ARG_REGS),
            implicit: ids(cc::IMPLICITLY_DEFINED_REGS),
            ret: ids(&[cc::INT_RETURN_REG])[0],
            ret_hi: ids(&[cc::HIGH_INT_RETURN_REG])[0],
        }
    }
}

impl AsRef<CoreCallingConvention> for Call0 {
    fn as_ref(&self) -> &CoreCallingConvention {
        &self.core
    }
}

impl CallingConvention for Call0 {
    fn caller_saved_registers(&self) -> Vec<RegisterId> {
        self.caller_saved.clone()
    }
    fn callee_saved_registers(&self) -> Vec<RegisterId> {
        Vec::new()
    }
    fn int_arg_registers(&self) -> Vec<RegisterId> {
        self.int_args.clone()
    }
    fn float_arg_registers(&self) -> Vec<RegisterId> {
        Vec::new()
    }
    fn arg_registers_shared_index(&self) -> bool {
        cc::ARG_REGS_SHARE_INDEX
    }
    fn reserved_stack_space_for_arg_registers(&self) -> bool {
        cc::STACK_RESERVED_FOR_ARG_REGS
    }
    fn stack_adjusted_on_return(&self) -> bool {
        cc::STACK_ADJUSTED_ON_RETURN
    }
    fn is_eligible_for_heuristics(&self) -> bool {
        cc::ELIGIBLE_FOR_HEURISTICS
    }
    fn return_int_reg(&self) -> Option<RegisterId> {
        Some(self.ret)
    }
    fn return_hi_int_reg(&self) -> Option<RegisterId> {
        Some(self.ret_hi)
    }
    fn return_float_reg(&self) -> Option<RegisterId> {
        None
    }
    fn global_pointer_reg(&self) -> Option<RegisterId> {
        None
    }
    fn implicitly_defined_registers(&self) -> Vec<RegisterId> {
        self.implicit.clone()
    }
    fn are_argument_registers_used_for_var_args(&self) -> bool {
        cc::ARG_REGS_FOR_VARARGS
    }
    /// Same answer as the core default (the register-stack top is 0, the
    /// rest undetermined) without the architecture round trips.
    fn incoming_register_value(&self, reg: RegisterId, _func: Option<&Function>) -> RegisterValue {
        if reg.0 == model::REG_STACK_TOP {
            RegisterValue::new(RegisterValueType::ConstantValue, 0, 0, 0)
        } else {
            RegisterValue::new(RegisterValueType::UndeterminedValue, 0, 0, 0)
        }
    }
}

pub fn register<A: Architecture>(arch: &A) -> binaryninja::rc::Ref<CoreCallingConvention> {
    binaryninja::calling_convention::register_calling_convention(arch, cc::NAME, Call0::new)
}
