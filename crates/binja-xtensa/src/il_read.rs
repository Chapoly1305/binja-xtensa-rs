//! Read access to existing LLIL functions over raw core handles, for the
//! function workflows, and a port of the Python API's `copy_expr_to`.
//!
//! The reference workflows read lifted IL through Binary Ninja's Python
//! wrappers (`source[i]`, `source.basic_blocks`, `block.outgoing_edges`,
//! `expr.operation`, `str(expr)` ...). Each helper here issues the core call
//! the wrapper issues. [`copy_expr_to`] is the Python
//! `LowLevelILFunction.copy_expr_to` (what `instruction.copy_to(dest)` runs),
//! ported case by case so the copied IL is built with the same builder calls
//! in the same order.

use std::ffi::{c_char, CStr, CString};
use std::ptr;

use binaryninjacore_sys::*;
use BNLowLevelILOperation::*;

use crate::il::{Il, Label, Loc, E};

/// An architecture handle obtained from the core (architectures are never
/// freed, so the handle is valid for the process lifetime).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arch(*mut BNArchitecture);

impl Arch {
    pub fn raw(self) -> *mut BNArchitecture {
        self.0
    }

    /// `arch.name`.
    pub fn name(self) -> String {
        if self.0.is_null() {
            return String::new();
        }
        // SAFETY: a live architecture; the returned string is copied and freed.
        unsafe {
            let p: *mut c_char = BNGetArchitectureName(self.0);
            if p.is_null() {
                return String::new();
            }
            let s = CStr::from_ptr(p).to_string_lossy().into_owned();
            BNFreeString(p);
            s
        }
    }
}

/// Owned `BNFunction` reference.
pub struct FunctionRef(*mut BNFunction);

impl Drop for FunctionRef {
    fn drop(&mut self) {
        // SAFETY: a reference this value owns.
        unsafe { BNFreeFunction(self.0) }
    }
}

impl FunctionRef {
    /// # Safety
    /// `raw` must be null or a new reference the caller owns.
    pub unsafe fn from_owned(raw: *mut BNFunction) -> Option<Self> {
        (!raw.is_null()).then_some(FunctionRef(raw))
    }

    /// `function.arch`.
    pub fn arch(&self) -> Arch {
        // SAFETY: live function.
        Arch(unsafe { BNGetFunctionArchitecture(self.0) })
    }
}

/// Owned `BNBinaryView` reference.
pub struct ViewRef(*mut BNBinaryView);

impl Drop for ViewRef {
    fn drop(&mut self) {
        // SAFETY: a reference this value owns.
        unsafe { BNFreeBinaryView(self.0) }
    }
}

impl ViewRef {
    /// # Safety
    /// `raw` must be null or a new reference the caller owns.
    pub unsafe fn from_owned(raw: *mut BNBinaryView) -> Option<Self> {
        (!raw.is_null()).then_some(ViewRef(raw))
    }

    /// `view.read(addr, length)`.
    pub fn read(&self, addr: u64, length: usize) -> Vec<u8> {
        let mut buf = vec![0u8; length];
        // SAFETY: live view; `buf` has room for `length` bytes.
        let n = unsafe { BNReadViewData(self.0, buf.as_mut_ptr().cast(), addr, length) };
        buf.truncate(n);
        buf
    }

    /// `settings.get_string(key, view)`.
    pub fn setting_string(&self, settings: &SettingsRef, key: &str) -> String {
        let key = CString::new(key).expect("setting keys contain no NUL");
        // SAFETY: live handles; the returned string is copied and freed.
        unsafe {
            let p = BNSettingsGetString(settings.0, key.as_ptr(), self.0, ptr::null_mut(), ptr::null_mut());
            if p.is_null() {
                return String::new();
            }
            let s = CStr::from_ptr(p).to_string_lossy().into_owned();
            BNFreeString(p);
            s
        }
    }
}

/// A `Settings` instance (`Settings()` is the `default` schema).
pub struct SettingsRef(*mut BNSettings);

// SAFETY: the core's settings objects are internally synchronized; the
// handle is only passed to core calls.
unsafe impl Send for SettingsRef {}
// SAFETY: as above.
unsafe impl Sync for SettingsRef {}

impl SettingsRef {
    /// `Settings(instance_id)`.
    pub fn new(instance_id: &str) -> Option<Self> {
        let id = CString::new(instance_id).ok()?;
        // SAFETY: plain core call; the result is a new reference (kept).
        let raw = unsafe { BNCreateSettings(id.as_ptr()) };
        (!raw.is_null()).then_some(SettingsRef(raw))
    }

    /// `settings.register_group(group, title)`.
    pub fn register_group(&self, group: &str, title: &str) -> bool {
        let (g, t) = (CString::new(group).expect("no NUL"), CString::new(title).expect("no NUL"));
        // SAFETY: live handle, valid C strings.
        unsafe { BNSettingsRegisterGroup(self.0, g.as_ptr(), t.as_ptr()) }
    }

    /// `settings.register_setting(key, properties)`.
    pub fn register_setting(&self, key: &str, properties: &str) -> bool {
        let (k, p) = (CString::new(key).expect("no NUL"), CString::new(properties).expect("no NUL"));
        // SAFETY: live handle, valid C strings.
        unsafe { BNSettingsRegisterSetting(self.0, k.as_ptr(), p.as_ptr()) }
    }
}

/// An owned reference to a core LLIL function (`BNFreeLowLevelILFunction` on
/// drop), like a Python `LowLevelILFunction` object.
pub struct Llil {
    raw: *mut BNLowLevelILFunction,
}

impl Drop for Llil {
    fn drop(&mut self) {
        // SAFETY: `raw` is a reference this value owns (see constructors).
        unsafe { BNFreeLowLevelILFunction(self.raw) }
    }
}

/// One expression as `BNGetLowLevelILByIndex` returns it.
#[derive(Clone, Copy, Debug)]
pub struct Expr {
    pub index: usize,
    pub op: BNLowLevelILOperation,
    pub size: usize,
    pub flags: u32,
    pub source_operand: u32,
    pub operands: [u64; 4],
    pub address: u64,
}

impl Expr {
    /// `ILSourceLocation.from_instruction(expr)`.
    pub fn loc(&self) -> Loc {
        Loc { address: self.address, source_operand: self.source_operand }
    }
}

/// An IL basic block (`LowLevelILBasicBlock`): instruction index range,
/// architecture, and an owned block reference for edge queries.
pub struct Block {
    raw: *mut BNBasicBlock,
    pub start: usize,
    pub end: usize,
    pub arch: Arch,
}

impl Drop for Block {
    fn drop(&mut self) {
        // SAFETY: `raw` is a reference obtained with `BNNewBasicBlockReference`.
        unsafe { BNFreeBasicBlock(self.raw) }
    }
}

impl Block {
    fn edges(&self, incoming: bool) -> Vec<usize> {
        let mut count = 0usize;
        // SAFETY: `raw` is a live block; the returned list is freed below and
        // only the block starts are kept.
        unsafe {
            let list = if incoming {
                BNGetBasicBlockIncomingEdges(self.raw, &mut count)
            } else {
                BNGetBasicBlockOutgoingEdges(self.raw, &mut count)
            };
            if list.is_null() {
                return Vec::new();
            }
            let out = std::slice::from_raw_parts(list, count)
                .iter()
                .map(|e| BNGetBasicBlockStart(e.target) as usize)
                .collect();
            BNFreeBasicBlockEdgeList(list, count);
            out
        }
    }

    /// `[edge.target.start for edge in block.outgoing_edges]`.
    pub fn outgoing(&self) -> Vec<usize> {
        self.edges(false)
    }

    /// `[edge.source.start for edge in block.incoming_edges]` (the core
    /// reports the other block of an incoming edge in its `target` field).
    pub fn incoming(&self) -> Vec<usize> {
        self.edges(true)
    }

}

impl Llil {
    /// Take ownership of a reference returned by the core (null = `None`).
    ///
    /// # Safety
    /// `raw` must be null or a new reference the caller owns.
    pub unsafe fn from_owned(raw: *mut BNLowLevelILFunction) -> Option<Self> {
        (!raw.is_null()).then_some(Llil { raw })
    }

    /// `LowLevelILFunction(arch, source_func=function)`.
    pub fn create(arch: Arch, function: &FunctionRef) -> Option<Self> {
        // SAFETY: both handles are live for the duration of the call; the
        // result is a new reference.
        unsafe { Self::from_owned(BNCreateLowLevelILFunction(arch.0, function.0)) }
    }

    pub fn raw(&self) -> *mut BNLowLevelILFunction {
        self.raw
    }

    /// `len(il)`.
    pub fn instruction_count(&self) -> usize {
        // SAFETY: live handle.
        unsafe { BNGetLowLevelILInstructionCount(self.raw) }
    }

    /// `il.get_expr_count()`.
    pub fn expr_count(&self) -> usize {
        // SAFETY: live handle.
        unsafe { BNGetLowLevelILExprCount(self.raw) }
    }

    /// `il.get_expr(index)`.
    pub fn expr(&self, index: usize) -> Expr {
        // SAFETY: live handle; the core bounds-checks the index.
        let i = unsafe { BNGetLowLevelILByIndex(self.raw, index) };
        Expr {
            index,
            op: i.operation,
            size: i.size,
            flags: i.flags,
            source_operand: i.sourceOperand,
            operands: i.operands,
            address: i.address,
        }
    }

    /// `il[i]`: the root expression of instruction `i`.
    pub fn instr(&self, i: usize) -> Expr {
        // SAFETY: live handle.
        let index = unsafe { BNGetLowLevelILIndexForInstruction(self.raw, i) };
        self.expr(index)
    }

    /// `BNLowLevelILGetOperandList(il, expr, operand)`.
    pub fn operand_list(&self, expr: usize, operand: usize) -> Vec<u64> {
        let mut count = 0usize;
        // SAFETY: live handle; the list is copied and freed.
        unsafe {
            let list = BNLowLevelILGetOperandList(self.raw, expr, operand, &mut count);
            if list.is_null() {
                return Vec::new();
            }
            let out = std::slice::from_raw_parts(list, count).to_vec();
            BNLowLevelILFreeOperandList(list);
            out
        }
    }

    /// `list(il.basic_blocks)`.
    pub fn blocks(&self) -> Vec<Block> {
        let mut count = 0usize;
        // SAFETY: live handle; each block gets its own reference before the
        // list is freed.
        unsafe {
            let list = BNGetLowLevelILBasicBlockList(self.raw, &mut count);
            if list.is_null() {
                return Vec::new();
            }
            let out = std::slice::from_raw_parts(list, count)
                .iter()
                .map(|&b| {
                    let raw = BNNewBasicBlockReference(b);
                    Block {
                        raw,
                        start: BNGetBasicBlockStart(raw) as usize,
                        end: BNGetBasicBlockEnd(raw) as usize,
                        arch: Arch(BNGetBasicBlockArchitecture(raw)),
                    }
                })
                .collect();
            BNFreeBasicBlockList(list, count);
            out
        }
    }

    /// `il.get_label_for_address(arch, addr)` read as `(label.resolved,
    /// label.operand)`.
    pub fn label_for_address(&self, arch: Arch, addr: u64) -> Option<(bool, usize)> {
        // SAFETY: live handle; a non-null label is owned by the function and
        // read immediately.
        unsafe {
            let p = BNGetLowLevelILLabelForAddress(self.raw, arch.0, addr);
            (!p.is_null()).then(|| ((*p).resolved, (*p).operand))
        }
    }

    /// `str(expr)`: the core's token text for an expression, concatenated.
    pub fn expr_text(&self, arch: Arch, expr: usize) -> Option<String> {
        let mut tokens: *mut BNInstructionTextToken = ptr::null_mut();
        let mut count = 0usize;
        // SAFETY: live handles; the token list is read and then freed.
        unsafe {
            if !BNGetLowLevelILExprText(self.raw, arch.0, expr, ptr::null_mut(), &mut tokens, &mut count) {
                return None;
            }
            let mut s = String::new();
            if !tokens.is_null() {
                for t in std::slice::from_raw_parts(tokens, count) {
                    if !t.text.is_null() {
                        s.push_str(&CStr::from_ptr(t.text).to_string_lossy());
                    }
                }
            }
            BNFreeInstructionText(tokens, count);
            Some(s)
        }
    }

    /// `il.replace_expr(original, new)`.
    pub fn replace_expr(&self, original: usize, new: E) {
        // SAFETY: live handle.
        unsafe { BNReplaceLowLevelILExpr(self.raw, original, new as usize) }
    }

    /// `il.prepare_to_copy_function(src)` on `self` as destination.
    pub fn prepare_to_copy_function(&self, src: &Llil) {
        // SAFETY: both handles live.
        unsafe { BNPrepareToCopyLowLevelILFunction(self.raw, src.raw) }
    }

    /// `il.prepare_to_copy_block(block)` on `self` as destination.
    pub fn prepare_to_copy_block(&self, block: &Block) {
        // SAFETY: both handles live.
        unsafe { BNPrepareToCopyLowLevelILBasicBlock(self.raw, block.raw) }
    }
}

/// `copy_expr_to` raised: `NotImplementedError` for an operation the Python
/// API does not copy. Propagates out of the activity like the Python
/// exception does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CopyUnsupported(pub BNLowLevelILOperation);

const UNARY: &[BNLowLevelILOperation] = &[
    LLIL_PUSH, LLIL_NEG, LLIL_NOT, LLIL_BSWAP, LLIL_POPCNT, LLIL_CLZ, LLIL_CTZ, LLIL_RBIT, LLIL_CLS, LLIL_ABS,
    LLIL_SX, LLIL_ZX, LLIL_LOW_PART, LLIL_BOOL_TO_INT, LLIL_UNIMPL_MEM, LLIL_FSQRT, LLIL_FNEG, LLIL_FABS,
    LLIL_FLOAT_TO_INT, LLIL_INT_TO_FLOAT, LLIL_FLOAT_CONV, LLIL_ROUND_TO_INT, LLIL_FLOOR, LLIL_CEIL, LLIL_FTRUNC,
];

const BINARY: &[BNLowLevelILOperation] = &[
    LLIL_ADD, LLIL_SUB, LLIL_AND, LLIL_OR, LLIL_XOR, LLIL_LSL, LLIL_LSR, LLIL_ASR, LLIL_ROL, LLIL_ROR, LLIL_MUL,
    LLIL_MINS, LLIL_MAXS, LLIL_MINU, LLIL_MAXU, LLIL_MULU_DP, LLIL_MULS_DP, LLIL_DIVU, LLIL_DIVS, LLIL_MODU,
    LLIL_MODS, LLIL_DIVU_DP, LLIL_DIVS_DP, LLIL_MODU_DP, LLIL_MODS_DP, LLIL_CMP_E, LLIL_CMP_NE, LLIL_CMP_SLT,
    LLIL_CMP_ULT, LLIL_CMP_SLE, LLIL_CMP_ULE, LLIL_CMP_SGE, LLIL_CMP_UGE, LLIL_CMP_SGT, LLIL_CMP_UGT,
    LLIL_TEST_BIT, LLIL_ADD_OVERFLOW, LLIL_FADD, LLIL_FSUB, LLIL_FMUL, LLIL_FDIV, LLIL_FCMP_E, LLIL_FCMP_NE,
    LLIL_FCMP_LT, LLIL_FCMP_LE, LLIL_FCMP_GE, LLIL_FCMP_GT, LLIL_FCMP_O, LLIL_FCMP_UO,
];

const CARRY: &[BNLowLevelILOperation] = &[LLIL_ADC, LLIL_SBB, LLIL_RLC, LLIL_RRC];

const NULLARY: &[BNLowLevelILOperation] = &[LLIL_POP, LLIL_NORET, LLIL_SYSCALL, LLIL_BP, LLIL_UNDEF, LLIL_UNIMPL];

/// `src.copy_expr_to(expr, dest)` with no `sub_expr_handler`, i.e.
/// `instruction.copy_to(dest)`.
///
/// Every case follows the Python method: sub-expressions are copied first, in
/// argument order, and the copy is built with the source location of the
/// original. Flag write types are passed through `expr.flags`, which the
/// Python wrapper turns into a name and back; the architecture has no flag
/// write types, so every name is `""` and maps back to 0.
pub fn copy_expr_to(src: &Llil, expr: &Expr, dest: &Il) -> Result<E, CopyUnsupported> {
    let sub = |operand: usize| copy_expr_to(src, &src.expr(expr.operands[operand] as usize), dest);
    let loc = expr.loc();
    let o = expr.operands;
    let size = expr.size;
    let op = expr.op;
    let e = |a: u64, b: u64, c: u64, d: u64, size: usize| dest.expr_at(loc, op, size, 0, a, b, c, d);
    Ok(match op {
        LLIL_NOP => e(0, 0, 0, 0, 0),
        // set_reg(size, dest, src): reg index, then the copied value.
        LLIL_SET_REG => {
            let v = sub(1)?;
            e(o[0], v, 0, 0, size)
        }
        LLIL_SET_REG_SPLIT => {
            let v = sub(2)?;
            e(o[0], o[1], v, 0, size)
        }
        LLIL_SET_REG_STACK_REL => {
            let d = sub(1)?;
            let v = sub(2)?;
            e(o[0], d, v, 0, size)
        }
        LLIL_REG_STACK_PUSH => {
            let v = sub(1)?;
            e(o[0], v, 0, 0, size)
        }
        // set_flag(flag, value): no size.
        LLIL_SET_FLAG => {
            let v = sub(1)?;
            e(o[0], v, 0, 0, 0)
        }
        LLIL_LOAD => {
            let v = sub(0)?;
            e(v, 0, 0, 0, size)
        }
        LLIL_STORE => {
            let d = sub(0)?;
            let v = sub(1)?;
            e(d, v, 0, 0, size)
        }
        LLIL_REG => e(o[0], 0, 0, 0, size),
        LLIL_REG_SPLIT => e(o[0], o[1], 0, 0, size),
        LLIL_REG_STACK_REL => {
            let v = sub(1)?;
            e(o[0], v, 0, 0, size)
        }
        LLIL_REG_STACK_POP => e(o[0], 0, 0, 0, size),
        LLIL_REG_STACK_FREE_REG => e(o[0], 0, 0, 0, 0),
        LLIL_REG_STACK_FREE_REL => {
            let v = sub(1)?;
            e(o[0], v, 0, 0, 0)
        }
        LLIL_FLAG => e(o[0], 0, 0, 0, 0),
        LLIL_FLAG_BIT => e(o[0], o[1], 0, 0, size),
        LLIL_JUMP | LLIL_CALL | LLIL_TAILCALL | LLIL_RET => {
            let v = sub(0)?;
            e(v, 0, 0, 0, 0)
        }
        LLIL_CALL_STACK_ADJUST => {
            // call_stack_adjust(dest, stack_adjustment, reg_stack_adjustments):
            // the adjustment map is rebuilt as an index list after `dest`.
            let v = sub(0)?;
            let list = src.operand_list(expr.index, 2);
            let l = dest.add_operand_list(&list);
            e(v, o[1], list.len() as u64, l, 0)
        }
        LLIL_JUMP_TO => {
            // `expr.targets`: a dict, so a repeated key keeps its first
            // position and its last value.
            let mut targets: Vec<(u64, u64)> = Vec::new();
            for kv in src.operand_list(expr.index, 1).chunks_exact(2) {
                match targets.iter_mut().find(|(k, _)| *k == kv[0]) {
                    Some(slot) => slot.1 = kv[1],
                    None => targets.push((kv[0], kv[1])),
                }
            }
            let mut labels: Vec<(u64, Label)> = Vec::with_capacity(targets.len());
            for (key, index) in targets {
                let Some(label) = dest.label_for_source_instruction(index as usize) else {
                    let v = sub(0)?;
                    return Ok(dest.expr_at(loc, LLIL_JUMP, 0, 0, v, 0, 0, 0));
                };
                labels.push((key, label));
            }
            let v = sub(0)?;
            let map = dest.add_label_map(&labels);
            e(v, (labels.len() * 2) as u64, map, 0, 0)
        }
        LLIL_GOTO => match dest.label_for_source_instruction(o[0] as usize) {
            Some(label) => dest.goto_at(label, loc),
            None => {
                let target = src.instr(o[0] as usize).address;
                let c = dest.const_pointer(crate::model::ADDRESS_SIZE, target as i64);
                dest.expr_at(loc, LLIL_JUMP, 0, 0, c, 0, 0, 0)
            }
        },
        LLIL_IF => {
            let t = dest.label_for_source_instruction(o[1] as usize);
            let f = dest.label_for_source_instruction(o[2] as usize);
            match (t, f) {
                (Some(t), Some(f)) => {
                    let c = sub(0)?;
                    dest.if_expr_at(c, t, f, loc)
                }
                _ => dest.expr_at(loc, LLIL_UNDEF, 0, 0, 0, 0, 0, 0),
            }
        }
        // flag_condition(cond, sem_class) and trap(vector): no size.
        LLIL_FLAG_COND => e(o[0], o[1], 0, 0, 0),
        LLIL_TRAP => e(o[0], 0, 0, 0, 0),
        LLIL_CONST | LLIL_CONST_PTR | LLIL_FLOAT_CONST => e(o[0], 0, 0, 0, size),
        LLIL_EXTERN_PTR => e(o[0], o[1], 0, 0, size),
        _ if NULLARY.contains(&op) => e(0, 0, 0, 0, size),
        _ if UNARY.contains(&op) => {
            let v = sub(0)?;
            e(v, 0, 0, 0, size)
        }
        _ if BINARY.contains(&op) => {
            let l = sub(0)?;
            let r = sub(1)?;
            e(l, r, 0, 0, size)
        }
        _ if CARRY.contains(&op) => {
            let l = sub(0)?;
            let r = sub(1)?;
            let c = sub(2)?;
            e(l, r, c, 0, size)
        }
        LLIL_INTRINSIC => {
            // params first, then CALL_PARAM (operand list, then expr, no
            // location), then the output list, then the INTRINSIC.
            let call_param = src.expr(o[3] as usize);
            let mut params = Vec::new();
            for p in src.operand_list(call_param.index, 0) {
                params.push(copy_expr_to(src, &src.expr(p as usize), dest)?);
            }
            let outputs = src.operand_list(expr.index, 0);
            let plist = dest.add_operand_list(&params);
            let cp = dest.expr(LLIL_CALL_PARAM, 0, params.len() as u64, plist, 0, 0);
            let olist = dest.add_operand_list(&outputs);
            dest.expr_at(loc, LLIL_INTRINSIC, 0, 0, outputs.len() as u64, olist, o[2], cp)
        }
        // ASSERT/FORCE_VER (rebuilt from cached value sets / versions),
        // FLAG_GROUP and everything else: not produced in Xtensa lifted IL.
        _ => return Err(CopyUnsupported(op)),
    })
}
