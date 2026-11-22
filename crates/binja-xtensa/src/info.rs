//! `get_instruction_info`: length and branch edges, as the reference computes
//! them from the mnemonic.

use std::sync::OnceLock;

use binaryninjacore_sys::BNBranchType;
use xtensa_isa::{decode, Insn, Opcode, OPCODE_COUNT};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    None,
    Return,
    Exception,
    Jump,
    IndirectJump,
    Call,
    IndirectCall,
    LoopNz,
    Loop,
    Conditional,
}

/// Mnemonic sets copied from the reference `get_instruction_info`. The
/// conditional set is the reference's `_target_offset_map` keys starting with
/// "B", compared after replacing "." by "_" (so `BBCI.L` is *not* a branch
/// there, and is not here).
fn class_of(mnemonic: &str) -> Class {
    const COND: [&str; 28] = [
        "BALL", "BANY", "BBC", "BBCI", "BBS", "BBSI", "BEQ", "BEQI", "BEQZ", "BEQZ_N", "BF", "BGE",
        "BGEI", "BGEU", "BGEUI", "BGEZ", "BLT", "BLTI", "BLTU", "BLTUI", "BLTZ", "BNALL", "BNE",
        "BNEI", "BNEZ", "BNEZ_N", "BNONE", "BT",
    ];
    match mnemonic {
        "RET" | "RET.N" | "RETW" | "RETW.N" => Class::Return,
        "RFUE" | "ILL" | "ILL.N" | "SYSCALL" => Class::Exception,
        "RFI" | "RFME" | "RFWO" | "RFWU" | "RFE" | "RFDE" => Class::Return,
        "J" => Class::Jump,
        "JX" => Class::IndirectJump,
        "CALL0" | "CALL4" | "CALL8" | "CALL12" => Class::Call,
        "CALLX0" | "CALLX4" | "CALLX8" | "CALLX12" => Class::IndirectCall,
        "LOOPNEZ" | "LOOPGTZ" => Class::LoopNz,
        "LOOP" => Class::Loop,
        m if COND.contains(&m.replace('.', "_").as_str()) => Class::Conditional,
        _ => Class::None,
    }
}

fn classes() -> &'static [Class; OPCODE_COUNT] {
    static TABLE: OnceLock<[Class; OPCODE_COUNT]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [Class::None; OPCODE_COUNT];
        for &op in Opcode::ALL {
            t[op as usize] = class_of(op.mnemonic());
        }
        t
    })
}

pub struct Info {
    pub length: usize,
    pub count: usize,
    pub kinds: [BNBranchType; 3],
    pub targets: [u64; 3],
}

impl Info {
    fn push(&mut self, kind: BNBranchType, target: u64) {
        self.kinds[self.count] = kind;
        self.targets[self.count] = target;
        self.count += 1;
    }
}

/// The reference decodes, treats an exception or `valid == False` as "no
/// instruction", and otherwise reports a length in 1..=3.
pub fn decoded(data: &[u8]) -> Option<Insn> {
    decode(data).ok().filter(|i| i.valid)
}

pub fn instruction_info(data: &[u8], addr: u64) -> Option<Info> {
    let insn = decoded(data)?;
    let length = match insn.len {
        1..=3 => insn.len as usize,
        _ => 3,
    };
    let mut info = Info {
        length,
        count: 0,
        kinds: [BNBranchType::UnconditionalBranch; 3],
        targets: [0; 3],
    };
    // Python integers wrapped into the core's u64 by ctypes.
    let target = |i: &Insn| i.target_offset(addr as u32).map(|t| t as u64);
    let next = addr.wrapping_add(length as u64);
    match classes()[insn.opcode as usize] {
        Class::None => {}
        Class::Return => info.push(BNBranchType::FunctionReturn, 0),
        Class::Exception => info.push(BNBranchType::ExceptionBranch, 0),
        Class::Jump => {
            if let Some(t) = target(&insn) {
                info.push(BNBranchType::UnconditionalBranch, t);
            }
        }
        Class::IndirectJump | Class::IndirectCall => info.push(BNBranchType::IndirectBranch, 0),
        Class::Call => {
            if let Some(t) = target(&insn) {
                info.push(BNBranchType::CallDestination, t);
            }
        }
        Class::LoopNz => {
            let imm8 = insn.imm8().unwrap_or(0) as u64;
            info.push(BNBranchType::TrueBranch, addr.wrapping_add(4).wrapping_add(imm8));
            info.push(BNBranchType::FalseBranch, next);
        }
        Class::Loop => info.push(BNBranchType::UnconditionalBranch, next),
        Class::Conditional => {
            if let Some(t) = target(&insn) {
                info.push(BNBranchType::TrueBranch, t);
            }
            info.push(BNBranchType::FalseBranch, next);
        }
    }
    Some(info)
}
