//! Xtensa (LX6/LX7) instruction decoder and disassembler.
//!
//! A bit-exact port of the reference Python decoder (`binja_xtensa`
//! `instruction.py` + `disassembly.py`), verified against an exhaustive
//! golden oracle covering all 2^24 three-byte encodings and every 1- and
//! 2-byte input. Reference quirks are reproduced on purpose; they are listed
//! in `ORACLE_QUIRKS.md`.
//!
//! ```
//! use xtensa_isa::{decode, disassemble, Opcode};
//!
//! // 0x004136: entry a1, 32
//! let insn = decode(&[0x36, 0x41, 0x00]).unwrap();
//! assert_eq!(insn.opcode, Opcode::Entry);
//! assert_eq!(insn.len, 3);
//! assert_eq!(insn.s(), Some(1));
//! assert_eq!(insn.inline0(), Some(32));
//!
//! let mut toks = Vec::new();
//! disassemble(&insn, 0x4008_0000, &mut toks);
//! let text: String = toks.iter().map(|t| t.text.as_str()).collect();
//! assert_eq!(text, "ENTRY   a1, 32");
//! ```
#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

mod decode;
mod disasm;
mod insn;
mod opcode;
pub mod oracle;
pub mod regs;

pub use decode::{decode, decode_word, DecodeError};
pub use disasm::{disassemble, Token, TokenKind, TokenText, TOKEN_TEXT_CAP};
pub use insn::{Field, Fields, Format, Insn, MacKind, MacOperation, MacReg};
pub use opcode::{Opcode, OPCODE_COUNT};
pub use regs::{SPECIAL_REGS, USER_REGS};

#[cfg(test)]
mod tests;
