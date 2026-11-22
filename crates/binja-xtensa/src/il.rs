//! A thin LLIL builder over the raw core API, method-for-method with the
//! Python `LowLevelILFunction` builder the reference lifter was written
//! against.
//!
//! Each method issues exactly the core calls the Python method issues, with
//! the same operand order, size and (always zero) flag-write type, so a
//! faithful port of a Python lifter function produces byte-identical IL.
//! Python names are kept (`and_expr`, `compare_signed_less_than`, ...) so that
//! the port can be reviewed side by side with the reference.
//!
//! Registers and intrinsics are passed by id ([`R`], [`I`]); use
//! [`crate::regs`] to resolve names. Expressions are plain indices ([`E`]),
//! as in Python.

use std::cell::RefCell;
use std::ptr;

use binaryninjacore_sys::*;
use BNLowLevelILOperation::*;

/// An expression index.
pub type E = u64;

/// A register id. Temporary registers are `LLIL_TEMP(n)` = `0x8000_0000 | n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct R(pub u32);

/// An intrinsic id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct I(pub u32);

/// `LLIL_TEMP(n)`.
pub const fn temp(n: u32) -> R {
    R(0x8000_0000 | n)
}

/// A label: either owned by this builder (Python `LowLevelILLabel()`), or a
/// core-owned label returned by `get_label_for_address`. Both are used by
/// pointer, exactly as in Python.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Label(*mut BNLowLevelILLabel);

pub struct Il {
    raw: *mut BNLowLevelILFunction,
    arch: *mut BNArchitecture,
    /// Labels created during this lift. Boxed so their addresses are stable;
    /// they live as long as the builder, like the Python objects did for the
    /// duration of the lift callback.
    #[allow(clippy::vec_box)]
    labels: RefCell<Vec<Box<BNLowLevelILLabel>>>,
}

impl Il {
    /// # Safety
    /// `raw` must be a valid LLIL function for the duration of the builder,
    /// and `arch` the architecture it is being lifted for.
    pub unsafe fn from_raw(raw: *mut BNLowLevelILFunction, arch: *mut BNArchitecture) -> Self {
        Il { raw, arch, labels: RefCell::new(Vec::new()) }
    }

    pub fn raw(&self) -> *mut BNLowLevelILFunction {
        self.raw
    }

    /// The architecture handle (`il.arch` in Python).
    pub fn arch(&self) -> *mut BNArchitecture {
        self.arch
    }

    // ------------------------------------------------------------ core ---

    /// `il.expr(op, a, b, c, d, size=size)` with no flags.
    #[inline]
    pub fn expr(&self, op: BNLowLevelILOperation, size: usize, a: u64, b: u64, c: u64, d: u64) -> E {
        unsafe { BNLowLevelILAddExpr(self.raw, op, size, 0, a, b, c, d) as E }
    }

    /// `il.append(expr)`; returns the instruction index.
    #[inline]
    pub fn append(&self, expr: E) -> u64 {
        unsafe { BNLowLevelILAddInstruction(self.raw, expr as usize) as u64 }
    }

    /// Number of instructions appended so far (`len(il)`).
    pub fn instruction_count(&self) -> usize {
        unsafe { BNGetLowLevelILInstructionCount(self.raw) }
    }

    pub fn add_operand_list(&self, operands: &[u64]) -> E {
        let mut ops = operands.to_vec();
        unsafe { BNLowLevelILAddOperandList(self.raw, ops.as_mut_ptr(), ops.len()) as E }
    }

    pub fn set_expr_attributes(&self, expr: E, attributes: u32) {
        unsafe { BNSetLowLevelILExprAttributes(self.raw, expr as usize, attributes) }
    }

    pub fn set_current_address(&self, addr: u64) {
        unsafe { BNLowLevelILSetCurrentAddress(self.raw, self.arch, addr) }
    }

    // ---------------------------------------------------------- labels ---

    /// `LowLevelILLabel()`.
    pub fn new_label(&self) -> Label {
        let mut label = Box::new(BNLowLevelILLabel { resolved: false, ref_: 0, operand: 0 });
        unsafe { BNLowLevelILInitLabel(&mut *label) };
        let p: *mut BNLowLevelILLabel = &mut *label;
        self.labels.borrow_mut().push(label);
        Label(p)
    }

    /// `il.get_label_for_address(arch, addr)` with `arch` = this IL's
    /// architecture (the reference passes `Architecture['xtensa']` or
    /// `il.arch`, which are the same architecture).
    pub fn get_label_for_address(&self, addr: u64) -> Option<Label> {
        let p = unsafe { BNGetLowLevelILLabelForAddress(self.raw, self.arch, addr) };
        (!p.is_null()).then_some(Label(p))
    }

    pub fn add_label_for_address(&self, addr: u64) {
        unsafe { BNAddLowLevelILLabelForAddress(self.raw, self.arch, addr) }
    }

    pub fn mark_label(&self, label: Label) {
        unsafe { BNLowLevelILMarkLabel(self.raw, label.0) }
    }

    pub fn if_expr(&self, cond: E, t: Label, f: Label) -> E {
        unsafe { BNLowLevelILIf(self.raw, cond, t.0, f.0) as E }
    }

    pub fn goto(&self, label: Label) -> E {
        unsafe { BNLowLevelILGoto(self.raw, label.0) as E }
    }

    // -------------------------------------------------- leaves & control ---

    /// Python passes the (possibly negative) integer straight to ctypes,
    /// which wraps it into the u64 operand.
    pub fn const_(&self, size: usize, value: i64) -> E {
        self.expr(LLIL_CONST, size, value as u64, 0, 0, 0)
    }
    pub fn const_pointer(&self, size: usize, value: i64) -> E {
        self.expr(LLIL_CONST_PTR, size, value as u64, 0, 0, 0)
    }
    pub fn float_const_single(&self, value: f32) -> E {
        self.expr(LLIL_FLOAT_CONST, 4, value.to_bits() as u64, 0, 0, 0)
    }
    pub fn reg(&self, size: usize, reg: R) -> E {
        self.expr(LLIL_REG, size, reg.0 as u64, 0, 0, 0)
    }
    pub fn set_reg(&self, size: usize, reg: R, value: E) -> E {
        self.expr(LLIL_SET_REG, size, reg.0 as u64, value, 0, 0)
    }
    pub fn reg_split(&self, size: usize, hi: R, lo: R) -> E {
        self.expr(LLIL_REG_SPLIT, size, hi.0 as u64, lo.0 as u64, 0, 0)
    }
    /// The only register stack is `physical_ar`, id 0.
    pub fn reg_stack_top_relative(&self, size: usize, entry: E) -> E {
        self.expr(LLIL_REG_STACK_REL, size, 0, entry, 0, 0)
    }
    pub fn set_reg_stack_top_relative(&self, size: usize, entry: E, value: E) -> E {
        self.expr(LLIL_SET_REG_STACK_REL, size, 0, entry, value, 0)
    }
    pub fn load(&self, size: usize, addr: E) -> E {
        self.expr(LLIL_LOAD, size, addr, 0, 0, 0)
    }
    pub fn store(&self, size: usize, addr: E, value: E) -> E {
        self.expr(LLIL_STORE, size, addr, value, 0, 0)
    }
    pub fn jump(&self, dest: E) -> E {
        self.expr(LLIL_JUMP, 0, dest, 0, 0, 0)
    }
    pub fn call(&self, dest: E) -> E {
        self.expr(LLIL_CALL, 0, dest, 0, 0, 0)
    }
    pub fn ret(&self, dest: E) -> E {
        self.expr(LLIL_RET, 0, dest, 0, 0, 0)
    }
    pub fn trap(&self, value: i64) -> E {
        self.expr(LLIL_TRAP, 0, value as u64, 0, 0, 0)
    }
    pub fn nop(&self) -> E {
        self.expr(LLIL_NOP, 0, 0, 0, 0, 0)
    }
    pub fn unimplemented(&self) -> E {
        self.expr(LLIL_UNIMPL, 0, 0, 0, 0, 0)
    }

    /// `il.intrinsic(outputs, intrinsic, params)`: the CALL_PARAM expression
    /// first, then the INTRINSIC, as in Python.
    pub fn intrinsic(&self, outputs: &[R], intrinsic: I, params: &[E]) -> E {
        let param_list = self.add_operand_list(params);
        let call_param = self.expr(LLIL_CALL_PARAM, 0, params.len() as u64, param_list, 0, 0);
        let outs: Vec<u64> = outputs.iter().map(|r| r.0 as u64).collect();
        let out_list = self.add_operand_list(&outs);
        self.expr(LLIL_INTRINSIC, 0, outputs.len() as u64, out_list, intrinsic.0 as u64, call_param)
    }
}

macro_rules! binary {
    ($($name:ident => $op:ident,)*) => {
        impl Il {
            $(
                #[inline]
                pub fn $name(&self, size: usize, a: E, b: E) -> E {
                    self.expr($op, size, a, b, 0, 0)
                }
            )*
        }
    };
}

macro_rules! unary {
    ($($name:ident => $op:ident,)*) => {
        impl Il {
            $(
                #[inline]
                pub fn $name(&self, size: usize, value: E) -> E {
                    self.expr($op, size, value, 0, 0, 0)
                }
            )*
        }
    };
}

binary! {
    add => LLIL_ADD,
    sub => LLIL_SUB,
    and_expr => LLIL_AND,
    or_expr => LLIL_OR,
    xor_expr => LLIL_XOR,
    shift_left => LLIL_LSL,
    logical_shift_right => LLIL_LSR,
    arith_shift_right => LLIL_ASR,
    mult => LLIL_MUL,
    mult_double_prec_unsigned => LLIL_MULU_DP,
    mult_double_prec_signed => LLIL_MULS_DP,
    div_unsigned => LLIL_DIVU,
    div_signed => LLIL_DIVS,
    mod_unsigned => LLIL_MODU,
    mod_signed => LLIL_MODS,
    test_bit => LLIL_TEST_BIT,
    compare_equal => LLIL_CMP_E,
    compare_not_equal => LLIL_CMP_NE,
    compare_signed_less_than => LLIL_CMP_SLT,
    compare_signed_less_equal => LLIL_CMP_SLE,
    compare_signed_greater_equal => LLIL_CMP_SGE,
    compare_unsigned_less_than => LLIL_CMP_ULT,
    compare_unsigned_less_equal => LLIL_CMP_ULE,
    compare_unsigned_greater_equal => LLIL_CMP_UGE,
    float_add => LLIL_FADD,
    float_sub => LLIL_FSUB,
    float_mult => LLIL_FMUL,
    float_compare_equal => LLIL_FCMP_E,
    float_compare_less_than => LLIL_FCMP_LT,
    float_compare_less_equal => LLIL_FCMP_LE,
    float_compare_greater_equal => LLIL_FCMP_GE,
    float_compare_ordered => LLIL_FCMP_O,
    float_compare_unordered => LLIL_FCMP_UO,
}

unary! {
    low_part => LLIL_LOW_PART,
    zero_extend => LLIL_ZX,
    sign_extend => LLIL_SX,
    not_expr => LLIL_NOT,
    neg_expr => LLIL_NEG,
    count_leading_zeros => LLIL_CLZ,
    count_leading_signs => LLIL_CLS,
    int_to_float => LLIL_INT_TO_FLOAT,
    round_to_int => LLIL_ROUND_TO_INT,
    floor => LLIL_FLOOR,
    ceil => LLIL_CEIL,
    float_trunc => LLIL_FTRUNC,
    float_neg => LLIL_FNEG,
    float_abs => LLIL_FABS,
}

#[allow(dead_code)]
fn _null() -> *mut BNLowLevelILFunction {
    ptr::null_mut()
}
