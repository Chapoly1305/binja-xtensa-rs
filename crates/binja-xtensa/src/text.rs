//! `get_instruction_text`: disassembly tokens in the core's token struct.

use std::cell::RefCell;
use std::ffi::CString;
use std::ptr;

use binaryninjacore_sys::{BNInstructionTextToken, BNInstructionTextTokenContext, BNInstructionTextTokenType};
use xtensa_isa::{disassemble, Token, TokenKind};

use crate::info::decoded;

fn kind(k: TokenKind) -> BNInstructionTextTokenType {
    match k {
        TokenKind::Text => BNInstructionTextTokenType::TextToken,
        TokenKind::Instruction => BNInstructionTextTokenType::InstructionToken,
        TokenKind::OperandSeparator => BNInstructionTextTokenType::OperandSeparatorToken,
        TokenKind::Register => BNInstructionTextTokenType::RegisterToken,
        TokenKind::Integer => BNInstructionTextTokenType::IntegerToken,
        TokenKind::PossibleAddress => BNInstructionTextTokenType::PossibleAddressToken,
    }
}

/// Field defaults are those of the reference's `InstructionTextToken`.
fn core_token(t: &Token) -> BNInstructionTextToken {
    BNInstructionTextToken {
        type_: kind(t.kind),
        text: CString::new(t.text.as_str()).expect("token text has no NUL").into_raw(),
        value: t.value as u64,
        width: 0,
        size: t.size as usize,
        operand: 0xffff_ffff,
        context: BNInstructionTextTokenContext::NoTokenContext,
        confidence: u8::MAX,
        address: 0,
        typeNames: ptr::null_mut(),
        namesCount: 0,
        exprIndex: usize::MAX,
    }
}

pub fn free_token_text(t: &BNInstructionTextToken) {
    if !t.text.is_null() {
        drop(unsafe { CString::from_raw(t.text) });
    }
}

thread_local! {
    static SCRATCH: RefCell<Vec<Token>> = const { RefCell::new(Vec::new()) };
}

pub fn instruction_text(data: &[u8], addr: u64) -> Option<(usize, Vec<BNInstructionTextToken>)> {
    let insn = decoded(data)?;
    SCRATCH.with_borrow_mut(|tokens| {
        tokens.clear();
        disassemble(&insn, addr as u32, tokens);
        Some((insn.len as usize, tokens.iter().map(core_token).collect()))
    })
}
