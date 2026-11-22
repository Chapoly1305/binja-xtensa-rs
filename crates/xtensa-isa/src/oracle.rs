//! The canonical oracle line format of `oracle/gen_golden.py`, used by the
//! `golden` example and the golden integration test.
//!
//! One line per input, tab separated:
//! `head len V|I mnem format fields inlines dis@0x40080000 dis@0x400D1233`,
//! or `head\tEXC IndexError` for a short input.

use crate::{decode, disassemble, Field, Token};
use std::io::Write as _;

/// The two addresses every `inline*` and disassembly is evaluated at.
pub const ADDRS: [u32; 2] = [0x4008_0000, 0x400D_1233];

/// Formats oracle lines, reusing a token buffer.
#[derive(Debug, Default)]
pub struct LineWriter {
    toks: Vec<Token>,
}

impl LineWriter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append the line for `bytes` (1 to 3 bytes), without a newline.
    ///
    /// The key is `{word:06x}` for three bytes, the byte string in hex
    /// otherwise.
    pub fn write_line(&mut self, bytes: &[u8], out: &mut Vec<u8>) {
        if let [b0, b1, b2] = *bytes {
            let word = u32::from_le_bytes([b0, b1, b2, 0]);
            let _ = write!(out, "{word:06x}");
        } else {
            for b in bytes {
                let _ = write!(out, "{b:02x}");
            }
        }
        let insn = match decode(bytes) {
            Ok(i) => i,
            Err(_) => {
                out.extend_from_slice(b"\tEXC IndexError");
                return;
            }
        };
        let _ = write!(
            out,
            "\t{}\t{}\t{}\t{}\t",
            insn.len,
            if insn.valid { 'V' } else { 'I' },
            insn.mnemonic(),
            insn.format.map_or("-", |f| f.name())
        );
        let mut first = true;
        for f in Field::ALL {
            if let Some(v) = insn.field(f) {
                if !first {
                    out.push(b',');
                }
                first = false;
                let _ = write!(out, "{}={v}", f.name());
            }
        }
        out.push(b'\t');
        let mut first = true;
        for n in 0..2u8 {
            if insn.inline(n, ADDRS[0]).is_none() {
                continue;
            }
            if !first {
                out.push(b',');
            }
            first = false;
            let a = insn.inline(n, ADDRS[0]).unwrap_or(0);
            let b = insn.inline(n, ADDRS[1]).unwrap_or(0);
            let _ = write!(out, "inline{n}={a}/{b}");
        }
        for addr in ADDRS {
            out.push(b'\t');
            self.toks.clear();
            disassemble(&insn, addr, &mut self.toks);
            for (i, t) in self.toks.iter().enumerate() {
                if i > 0 {
                    out.push(b'|');
                }
                let _ = write!(
                    out,
                    "{}:{}:{}:{}",
                    t.kind.tag(),
                    t.text.as_str(),
                    t.value,
                    t.size
                );
            }
        }
    }

    /// The full contents of shard `hi` (all words `hi << 16 | lo`).
    pub fn shard(&mut self, hi: u8, out: &mut Vec<u8>) {
        for lo in 0..=0xffffu32 {
            let w = ((hi as u32) << 16) | lo;
            self.write_line(&[w as u8, (w >> 8) as u8, hi], out);
            out.push(b'\n');
        }
    }

    /// The full contents of `short.tsv` (all 1-byte, then all 2-byte inputs).
    pub fn short(&mut self, out: &mut Vec<u8>) {
        for w in 0..=0xffu8 {
            self.write_line(&[w], out);
            out.push(b'\n');
        }
        for w in 0..=0xffffu16 {
            self.write_line(&w.to_le_bytes(), out);
            out.push(b'\n');
        }
    }
}
