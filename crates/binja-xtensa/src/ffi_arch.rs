//! Architecture registration through the raw core API.
//!
//! The reference plugin registers its architecture with `BNRegisterArchitecture`
//! and fills a `BNCustomArchitecture` with callbacks. This module does the
//! same, for two reasons:
//!
//! * Lifting needs the raw `BNLowLevelILFunction` handle, so that every
//!   expression is built with the same core calls (`BNLowLevelILAddExpr`,
//!   label pointers from the address map, operand lists) as the reference
//!   and the resulting IL is identical, not merely equivalent.
//! * Every query the core makes is answered from static tables, without the
//!   per-call allocations of a generic wrapper.
//!
//! Callback behaviour (including what is returned for unknown ids and on
//! failure) follows the reference implementation in Binary Ninja's
//! `architecture.py`, which is what the Python plugin ran on.

use std::ffi::{c_char, c_void, CStr, CString};
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};

use binaryninjacore_sys::*;

use crate::{info, lift, model, text};

static ARCH: AtomicPtr<BNArchitecture> = AtomicPtr::new(ptr::null_mut());

/// The registered core architecture handle (null before registration).
pub fn handle() -> *mut BNArchitecture {
    ARCH.load(Ordering::Acquire)
}

// ---------------------------------------------------------------- lists ---

/// Lists handed to the core are boxed slices; the core gives them back to
/// `free_register_list` with their length.
fn leak_list(items: Vec<u32>, count: *mut usize) -> *mut u32 {
    let boxed = items.into_boxed_slice();
    unsafe { *count = boxed.len() };
    Box::into_raw(boxed) as *mut u32
}

extern "C" fn free_register_list(_ctxt: *mut c_void, regs: *mut u32, count: usize) {
    if regs.is_null() {
        return;
    }
    unsafe { drop(Box::from_raw(ptr::slice_from_raw_parts_mut(regs, count))) };
}

fn alloc_str(s: &str) -> *mut c_char {
    let c = CString::new(s).expect("names contain no NUL");
    unsafe { BNAllocString(c.as_ptr()) }
}

// ------------------------------------------------------------ constants ---

extern "C" fn init(_ctxt: *mut c_void, obj: *mut BNArchitecture) {
    ARCH.store(obj, Ordering::Release);
}
extern "C" fn endianness(_ctxt: *mut c_void) -> BNEndianness {
    BNEndianness::LittleEndian
}
extern "C" fn address_size(_ctxt: *mut c_void) -> usize {
    model::ADDRESS_SIZE
}
extern "C" fn default_integer_size(_ctxt: *mut c_void) -> usize {
    model::DEFAULT_INT_SIZE
}
extern "C" fn instruction_alignment(_ctxt: *mut c_void) -> usize {
    model::INSTR_ALIGNMENT
}
extern "C" fn max_instruction_length(_ctxt: *mut c_void) -> usize {
    model::MAX_INSTR_LENGTH
}
extern "C" fn opcode_display_length(_ctxt: *mut c_void) -> usize {
    model::MAX_INSTR_LENGTH
}
extern "C" fn linear_sweep_initial_alignment(_ctxt: *mut c_void) -> usize {
    model::INSTR_ALIGNMENT
}
extern "C" fn linear_sweep_analysis_capabilities(_ctxt: *mut c_void) -> u32 {
    BNLinearSweepAnalysisCapability::BNLinearSweepCallTargetAnalysis as u32
        | BNLinearSweepAnalysisCapability::BNLinearSweepGenericControlFlowAnalysis as u32
}
extern "C" fn associated_arch_by_address(_ctxt: *mut c_void, _addr: *mut u64) -> *mut BNArchitecture {
    handle()
}

// ---------------------------------------------------------- instructions ---

/// # Safety
/// The core passes `len` readable bytes at `data`.
unsafe fn bytes<'a>(data: *const u8, len: usize) -> &'a [u8] {
    if data.is_null() || len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(data, len)
    }
}

extern "C" fn get_instruction_info(
    _ctxt: *mut c_void,
    data: *const u8,
    addr: u64,
    max_len: usize,
    result: *mut BNInstructionInfo,
) -> bool {
    let data = unsafe { bytes(data, max_len) };
    let Some(i) = info::instruction_info(data, addr) else {
        return false;
    };
    let r = unsafe { &mut *result };
    r.length = i.length;
    r.archTransitionByTargetAddr = false;
    r.delaySlots = 0;
    r.branchCount = i.count;
    for k in 0..i.count {
        r.branchType[k] = i.kinds[k];
        r.branchTarget[k] = i.targets[k];
        r.branchArch[k] = ptr::null_mut();
    }
    true
}

extern "C" fn get_instruction_text(
    _ctxt: *mut c_void,
    data: *const u8,
    addr: u64,
    len: *mut usize,
    result: *mut *mut BNInstructionTextToken,
    count: *mut usize,
) -> bool {
    let data = unsafe { bytes(data, *len) };
    let Some((length, tokens)) = text::instruction_text(data, addr) else {
        return false;
    };
    let tokens: Box<[BNInstructionTextToken]> = tokens.into_boxed_slice();
    unsafe {
        *len = length;
        *count = tokens.len();
        *result = Box::into_raw(tokens) as *mut BNInstructionTextToken;
    }
    true
}

extern "C" fn get_instruction_text_with_context(
    ctxt: *mut c_void,
    data: *const u8,
    addr: u64,
    len: *mut usize,
    _context: *mut c_void,
    result: *mut *mut BNInstructionTextToken,
    count: *mut usize,
) -> bool {
    get_instruction_text(ctxt, data, addr, len, result, count)
}

extern "C" fn free_instruction_text(tokens: *mut BNInstructionTextToken, count: usize) {
    if tokens.is_null() {
        return;
    }
    let tokens = unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(tokens, count)) };
    for t in tokens.iter() {
        text::free_token_text(t);
    }
}

extern "C" fn get_instruction_low_level_il(
    _ctxt: *mut c_void,
    data: *const u8,
    addr: u64,
    len: *mut usize,
    il: *mut BNLowLevelILFunction,
) -> bool {
    let data = unsafe { bytes(data, *len) };
    let il = unsafe { crate::il::Il::from_raw(il, handle()) };
    match lift::instruction_llil(data, addr, &il) {
        Some(length) => {
            unsafe { *len = length };
            true
        }
        None => false,
    }
}

extern "C" fn analyze_basic_blocks(
    _ctxt: *mut c_void,
    function: *mut BNFunction,
    context: *mut BNBasicBlockAnalysisContext,
) {
    unsafe { BNArchitectureDefaultAnalyzeBasicBlocks(function, context) }
}

extern "C" fn lift_function(
    _ctxt: *mut c_void,
    function: *mut BNLowLevelILFunction,
    context: *mut BNFunctionLifterContext,
) -> bool {
    unsafe { BNArchitectureDefaultLiftFunction(function, context) }
}

extern "C" fn free_function_arch_context(_ctxt: *mut c_void, _context: *mut c_void) {}

// ------------------------------------------------------------ registers ---

extern "C" fn get_register_name(_ctxt: *mut c_void, reg: u32) -> *mut c_char {
    alloc_str(model::REGISTERS.get(reg as usize).map_or("", |r| r.0))
}

extern "C" fn all_registers(_ctxt: *mut c_void, count: *mut usize) -> *mut u32 {
    leak_list((0..model::REGISTERS.len() as u32).collect(), count)
}

extern "C" fn empty_list(_ctxt: *mut c_void, count: *mut usize) -> *mut u32 {
    leak_list(Vec::new(), count)
}

extern "C" fn get_register_info(_ctxt: *mut c_void, reg: u32, result: *mut BNRegisterInfo) {
    let r = unsafe { &mut *result };
    match model::REGISTERS.get(reg as usize) {
        Some(&(_, size)) => {
            r.fullWidthRegister = reg;
            r.offset = 0;
            r.size = size as usize;
        }
        None => {
            r.fullWidthRegister = 0;
            r.offset = 0;
            r.size = 0;
        }
    }
    r.extend = BNImplicitRegisterExtend::NoExtend;
}

extern "C" fn stack_pointer_register(_ctxt: *mut c_void) -> u32 {
    model::STACK_POINTER
}
extern "C" fn link_register(_ctxt: *mut c_void) -> u32 {
    model::LINK_REG
}

extern "C" fn get_register_stack_name(_ctxt: *mut c_void, reg_stack: u32) -> *mut c_char {
    alloc_str(if reg_stack == 0 { model::REG_STACK_NAME } else { "" })
}

extern "C" fn all_register_stacks(_ctxt: *mut c_void, count: *mut usize) -> *mut u32 {
    leak_list(vec![0], count)
}

extern "C" fn get_register_stack_info(_ctxt: *mut c_void, reg_stack: u32, result: *mut BNRegisterStackInfo) {
    let r = unsafe { &mut *result };
    r.firstTopRelativeReg = 0;
    r.topRelativeCount = 0;
    if reg_stack == 0 {
        r.firstStorageReg = model::REG_STACK_STORAGE_FIRST;
        r.storageCount = model::REG_STACK_STORAGE_COUNT as u32;
        r.stackTopReg = model::REG_STACK_TOP;
    } else {
        r.firstStorageReg = 0;
        r.storageCount = 0;
        r.stackTopReg = 0;
    }
}

// ---------------------------------------------------------------- flags ---
// Xtensa has no flags; these exist because the core calls them regardless.

extern "C" fn get_flag_name(_ctxt: *mut c_void, _id: u32) -> *mut c_char {
    alloc_str("")
}
extern "C" fn get_flag_role(_ctxt: *mut c_void, _flag: u32, _sem_class: u32) -> BNFlagRole {
    BNFlagRole::SpecialFlagRole
}
extern "C" fn flags_required_for_flag_condition(
    _ctxt: *mut c_void,
    _cond: BNLowLevelILFlagCondition,
    _sem_class: u32,
    count: *mut usize,
) -> *mut u32 {
    leak_list(Vec::new(), count)
}
extern "C" fn flags_required_for_semantic_flag_group(_ctxt: *mut c_void, _g: u32, count: *mut usize) -> *mut u32 {
    leak_list(Vec::new(), count)
}
extern "C" fn flag_conditions_for_semantic_flag_group(
    _ctxt: *mut c_void,
    _g: u32,
    count: *mut usize,
) -> *mut BNFlagConditionForSemanticClass {
    unsafe { *count = 0 };
    ptr::null_mut()
}
extern "C" fn free_flag_conditions_for_semantic_flag_group(
    _ctxt: *mut c_void,
    _c: *mut BNFlagConditionForSemanticClass,
    _count: usize,
) {
}
extern "C" fn flags_written_by_flag_write_type(_ctxt: *mut c_void, _w: u32, count: *mut usize) -> *mut u32 {
    leak_list(Vec::new(), count)
}
extern "C" fn semantic_class_for_flag_write_type(_ctxt: *mut c_void, _w: u32) -> u32 {
    0
}
fn unimplemented_expr(il: *mut BNLowLevelILFunction) -> usize {
    unsafe { BNLowLevelILAddExpr(il, BNLowLevelILOperation::LLIL_UNIMPL, 0, 0, 0, 0, 0, 0) as usize }
}
extern "C" fn flag_write_llil(
    _ctxt: *mut c_void,
    _op: BNLowLevelILOperation,
    _size: usize,
    _write_type: u32,
    _flag: u32,
    _operands: *mut BNRegisterOrConstant,
    _operand_count: usize,
    il: *mut BNLowLevelILFunction,
) -> usize {
    unimplemented_expr(il)
}
extern "C" fn flag_condition_llil(
    _ctxt: *mut c_void,
    _cond: BNLowLevelILFlagCondition,
    _sem_class: u32,
    il: *mut BNLowLevelILFunction,
) -> usize {
    unimplemented_expr(il)
}
extern "C" fn semantic_flag_group_llil(_ctxt: *mut c_void, _g: u32, il: *mut BNLowLevelILFunction) -> usize {
    unimplemented_expr(il)
}

// ----------------------------------------------------------- intrinsics ---

extern "C" fn intrinsic_class(_ctxt: *mut c_void, _intrinsic: u32) -> BNIntrinsicClass {
    BNIntrinsicClass::GeneralIntrinsicClass
}
extern "C" fn intrinsic_name(_ctxt: *mut c_void, intrinsic: u32) -> *mut c_char {
    alloc_str(model::INTRINSICS.get(intrinsic as usize).map_or("", |d| d.name))
}
extern "C" fn all_intrinsics(_ctxt: *mut c_void, count: *mut usize) -> *mut u32 {
    leak_list((0..model::INTRINSICS.len() as u32).collect(), count)
}

fn scalar_type(t: model::ScalarType) -> *mut BNType {
    match t {
        model::ScalarType::U32 => {
            let mut sign = BNBoolWithConfidence { value: false, confidence: u8::MAX };
            unsafe { BNCreateIntegerType(4, &mut sign, c"".as_ptr()) }
        }
    }
}

extern "C" fn intrinsic_inputs(_ctxt: *mut c_void, intrinsic: u32, count: *mut usize) -> *mut BNNameAndType {
    let Some(def) = model::INTRINSICS.get(intrinsic as usize) else {
        unsafe { *count = 0 };
        return ptr::null_mut();
    };
    let list: Box<[BNNameAndType]> = def
        .inputs
        .iter()
        .map(|&(name, t)| BNNameAndType {
            name: alloc_str(name),
            type_: scalar_type(t),
            typeConfidence: u8::MAX,
        })
        .collect();
    unsafe { *count = list.len() };
    Box::into_raw(list) as *mut BNNameAndType
}

extern "C" fn free_name_and_type_list(_ctxt: *mut c_void, nt: *mut BNNameAndType, count: usize) {
    if nt.is_null() {
        return;
    }
    let list = unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(nt, count)) };
    for e in list.iter() {
        unsafe {
            BNFreeString(e.name);
            BNFreeType(e.type_);
        }
    }
}

extern "C" fn intrinsic_outputs(_ctxt: *mut c_void, intrinsic: u32, count: *mut usize) -> *mut BNTypeWithConfidence {
    let Some(def) = model::INTRINSICS.get(intrinsic as usize) else {
        unsafe { *count = 0 };
        return ptr::null_mut();
    };
    let list: Box<[BNTypeWithConfidence]> = def
        .outputs
        .iter()
        .map(|&t| BNTypeWithConfidence { type_: scalar_type(t), confidence: u8::MAX })
        .collect();
    unsafe { *count = list.len() };
    Box::into_raw(list) as *mut BNTypeWithConfidence
}

extern "C" fn free_type_list(_ctxt: *mut c_void, types: *mut BNTypeWithConfidence, count: usize) {
    if types.is_null() {
        return;
    }
    let list = unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(types, count)) };
    for e in list.iter() {
        unsafe { BNFreeType(e.type_) };
    }
}

// ---------------------------------------------------- assembly/patching ---

extern "C" fn can_assemble(_ctxt: *mut c_void) -> bool {
    false
}
extern "C" fn assemble(
    _ctxt: *mut c_void,
    _code: *const c_char,
    _addr: u64,
    _result: *mut BNDataBuffer,
    errors: *mut *mut c_char,
) -> bool {
    unsafe { *errors = alloc_str("Architecture does not implement an assembler.\n") };
    false
}
extern "C" fn patch_query(_ctxt: *mut c_void, _data: *const u8, _addr: u64, _len: usize) -> bool {
    false
}
extern "C" fn patch_apply(_ctxt: *mut c_void, _data: *mut u8, _addr: u64, _len: usize) -> bool {
    false
}
extern "C" fn skip_and_return_value(_ctxt: *mut c_void, _data: *mut u8, _addr: u64, _len: usize, _v: u64) -> bool {
    false
}

// --------------------------------------------------------- registration ---

/// Register the architecture under `name` and return its core handle.
pub fn register(name: &str) -> *mut BNArchitecture {
    let mut cb = BNCustomArchitecture {
        context: ptr::null_mut(),
        init: Some(init),
        getEndianness: Some(endianness),
        getAddressSize: Some(address_size),
        getDefaultIntegerSize: Some(default_integer_size),
        getInstructionAlignment: Some(instruction_alignment),
        getMaxInstructionLength: Some(max_instruction_length),
        getOpcodeDisplayLength: Some(opcode_display_length),
        getAssociatedArchitectureByAddress: Some(associated_arch_by_address),
        getInstructionInfo: Some(get_instruction_info),
        getInstructionText: Some(get_instruction_text),
        getInstructionTextWithContext: Some(get_instruction_text_with_context),
        freeInstructionText: Some(free_instruction_text),
        getInstructionLowLevelIL: Some(get_instruction_low_level_il),
        analyzeBasicBlocks: Some(analyze_basic_blocks),
        liftFunction: Some(lift_function),
        freeFunctionArchContext: Some(free_function_arch_context),
        getRegisterName: Some(get_register_name),
        getFlagName: Some(get_flag_name),
        getFlagWriteTypeName: Some(get_flag_name),
        getSemanticFlagClassName: Some(get_flag_name),
        getSemanticFlagGroupName: Some(get_flag_name),
        getFullWidthRegisters: Some(all_registers),
        getAllRegisters: Some(all_registers),
        getAllFlags: Some(empty_list),
        getAllFlagWriteTypes: Some(empty_list),
        getAllSemanticFlagClasses: Some(empty_list),
        getAllSemanticFlagGroups: Some(empty_list),
        getFlagRole: Some(get_flag_role),
        getFlagsRequiredForFlagCondition: Some(flags_required_for_flag_condition),
        getFlagsRequiredForSemanticFlagGroup: Some(flags_required_for_semantic_flag_group),
        getFlagConditionsForSemanticFlagGroup: Some(flag_conditions_for_semantic_flag_group),
        freeFlagConditionsForSemanticFlagGroup: Some(free_flag_conditions_for_semantic_flag_group),
        getFlagsWrittenByFlagWriteType: Some(flags_written_by_flag_write_type),
        getSemanticClassForFlagWriteType: Some(semantic_class_for_flag_write_type),
        getFlagWriteLowLevelIL: Some(flag_write_llil),
        getFlagConditionLowLevelIL: Some(flag_condition_llil),
        getSemanticFlagGroupLowLevelIL: Some(semantic_flag_group_llil),
        freeRegisterList: Some(free_register_list),
        getRegisterInfo: Some(get_register_info),
        getStackPointerRegister: Some(stack_pointer_register),
        getLinkRegister: Some(link_register),
        getGlobalRegisters: Some(empty_list),
        getSystemRegisters: Some(empty_list),
        getRegisterStackName: Some(get_register_stack_name),
        getAllRegisterStacks: Some(all_register_stacks),
        getRegisterStackInfo: Some(get_register_stack_info),
        getIntrinsicClass: Some(intrinsic_class),
        getIntrinsicName: Some(intrinsic_name),
        getAllIntrinsics: Some(all_intrinsics),
        getIntrinsicInputs: Some(intrinsic_inputs),
        freeNameAndTypeList: Some(free_name_and_type_list),
        getIntrinsicOutputs: Some(intrinsic_outputs),
        freeTypeList: Some(free_type_list),
        canAssemble: Some(can_assemble),
        assemble: Some(assemble),
        isNeverBranchPatchAvailable: Some(patch_query),
        isAlwaysBranchPatchAvailable: Some(patch_query),
        isInvertBranchPatchAvailable: Some(patch_query),
        isSkipAndReturnZeroPatchAvailable: Some(patch_query),
        isSkipAndReturnValuePatchAvailable: Some(patch_query),
        convertToNop: Some(patch_apply),
        alwaysBranch: Some(patch_apply),
        invertBranch: Some(patch_apply),
        skipAndReturnValue: Some(skip_and_return_value),
        getLinearSweepInitialAlignment: Some(linear_sweep_initial_alignment),
        getLinearSweepAnalysisCapabilities: Some(linear_sweep_analysis_capabilities),
    };
    let cname = CString::new(name).expect("architecture name has no NUL");
    let arch = unsafe { BNRegisterArchitecture(cname.as_ptr(), &mut cb) };
    ARCH.store(arch, Ordering::Release);
    arch
}

/// Name of a register id, for diagnostics.
pub fn register_name(id: u32) -> &'static str {
    model::REGISTERS.get(id as usize).map_or("", |r| r.0)
}

#[allow(dead_code)]
fn _assert_cstr(_: &CStr) {}
