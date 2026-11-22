//! The table walk. This is a direct transcription of `Instruction.decode` in
//! the reference `instruction.py` (Xtensa ISA manual section 7.3.1 opcode
//! maps), including its quirks; see `ORACLE_QUIRKS.md`.
//!
//! The walk runs on the first three bytes, zero-padded. Every byte read of
//! the reference decoder assigns a field, so the set of fields present at the
//! end tells exactly which bytes the reference would have read; a short input
//! is rejected iff one of those bytes is missing (the reference raises
//! `IndexError` at that read).

use crate::insn::{field as f, Format, Insn};
use crate::opcode::Opcode as O;

/// Why [`decode`] produced no instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DecodeError {
    /// The encoding needs more bytes than were supplied (the reference
    /// decoder raises `IndexError`). Includes the empty input.
    ShortInput,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, fm: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecodeError::ShortInput => fm.write_str("not enough bytes for this encoding"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Fields read from byte 1 and byte 2, respectively.
const NEEDS_B1: u32 = f::R | f::S | f::SR | f::IMM6 | f::IMM7 | f::IMM12 | f::IMM16 | f::OFFSET;
const NEEDS_B2: u32 = f::OP1 | f::OP2 | f::IMM4 | f::IMM8 | f::IMM12 | f::IMM16 | f::OFFSET;

const fn format_fields(fmt: Format) -> u32 {
    match fmt {
        Format::Rrr => f::OP2 | f::T | f::S | f::R,
        Format::Rsr => f::T | f::SR,
        Format::Callx => f::N | f::M | f::S | f::R,
        Format::Rri4 => f::R | f::S | f::T | f::IMM4,
        Format::Rri8 => f::R | f::S | f::T | f::IMM8,
        Format::Ri16 => f::T | f::IMM16,
        Format::Call => f::N | f::OFFSET,
        Format::Bri8 => f::R | f::S | f::M | f::N | f::IMM8,
        Format::Bri12 => f::S | f::M | f::N | f::IMM12,
        Format::Rrrn => f::R | f::S | f::T,
        Format::Ri7 => f::S | f::I | f::IMM7,
        Format::Ri6 => f::S | f::I | f::Z | f::IMM6,
    }
}

const fn format_len(fmt: Format) -> u8 {
    match fmt {
        Format::Rrrn | Format::Ri7 | Format::Ri6 => 2,
        _ => 3,
    }
}

/// Decode one instruction from the start of `bytes`.
///
/// Reads at most three bytes. Mirrors the reference decoder exactly: reserved
/// or unimplemented slots decode to an invalid `ILL` with `format == None` and
/// `len == 3` (even for 1- and 2-byte inputs whose first byte selects such a
/// slot), and an input too short for the bytes the walk reads is
/// [`DecodeError::ShortInput`].
#[inline]
pub fn decode(bytes: &[u8]) -> Result<Insn, DecodeError> {
    let insn = match *bytes {
        [b0, b1, b2, ..] => return Ok(walk([b0, b1, b2])),
        [b0, b1] => walk([b0, b1, 0]),
        [b0] => walk([b0, 0, 0]),
        [] => return Err(DecodeError::ShortInput),
    };
    let present = insn.present_mask();
    let needed = if present & NEEDS_B2 != 0 {
        3
    } else if present & NEEDS_B1 != 0 {
        2
    } else {
        1
    };
    if needed > bytes.len() {
        Err(DecodeError::ShortInput)
    } else {
        Ok(insn)
    }
}

/// Decode a three-byte little-endian word (bits 24..31 are ignored).
#[inline]
pub fn decode_word(word: u32) -> Insn {
    walk([word as u8, (word >> 8) as u8, (word >> 16) as u8])
}

#[inline(always)]
fn leaf(w: [u8; 3], mask: u32, op: O, fmt: Format, valid: bool) -> Insn {
    Insn::from_parts(
        op,
        format_len(fmt),
        valid,
        Some(fmt),
        mask | format_fields(fmt),
        w,
    )
}

/// Reserved slot: `_call_from_map` fallback (mnem "ILL", invalid, length 3,
/// no instruction type, only the fields read so far).
#[inline(always)]
fn ill(w: [u8; 3], mask: u32) -> Insn {
    Insn::from_parts(O::Ill, 3, false, None, mask, w)
}

#[inline]
fn walk(w: [u8; 3]) -> Insn {
    let op0 = w[0] & 0xf;
    let t = w[0] >> 4;
    let n = (w[0] >> 4) & 3;
    let m = w[0] >> 6;
    let s = w[1] & 0xf;
    let r = w[1] >> 4;
    let op1 = w[2] & 0xf;
    let op2 = w[2] >> 4;

    use Format::*;
    let k = f::OP0;
    // Short-hands: `rrr!(Op)` is an RRR leaf that is always valid, etc.
    macro_rules! lf {
        ($mask:expr, $op:ident, $fmt:ident) => {
            leaf(w, $mask, O::$op, $fmt, true)
        };
        ($mask:expr, $op:ident, $fmt:ident, $valid:expr) => {
            leaf(w, $mask, O::$op, $fmt, $valid)
        };
    }

    match op0 {
        0 => {
            // QRST
            let k = k | f::OP1;
            match op1 {
                0 => {
                    // RST0
                    let k = k | f::OP2;
                    match op2 {
                        0 => {
                            // ST0
                            let k = k | f::R;
                            match r {
                                0 => {
                                    // SNM0
                                    let k = k | f::M;
                                    match m {
                                        0 => lf!(k, Ill, Callx, s == 0 && n == 0),
                                        2 => {
                                            let k = k | f::N;
                                            match n {
                                                0 => lf!(k, Ret, Callx, s == 0),
                                                1 => lf!(k, Retw, Callx, s == 0),
                                                2 => lf!(k, Jx, Callx),
                                                _ => ill(w, k),
                                            }
                                        }
                                        3 => {
                                            let k = k | f::N;
                                            let op = [O::Callx0, O::Callx4, O::Callx8, O::Callx12]
                                                [n as usize];
                                            leaf(w, k, op, Callx, true)
                                        }
                                        _ => ill(w, k),
                                    }
                                }
                                1 => lf!(k, Movsp, Rrr),
                                2 => {
                                    // SYNC
                                    let k = k | f::T;
                                    let op = match t {
                                        0 => O::Isync,
                                        1 => O::Rsync,
                                        2 => O::Esync,
                                        3 => O::Dsync,
                                        8 => O::Excw,
                                        12 => O::Memw,
                                        13 => O::Extw,
                                        15 => O::Nop,
                                        _ => return ill(w, k),
                                    };
                                    leaf(w, k, op, Rrr, s == 0)
                                }
                                3 => {
                                    // RFEI
                                    let k = k | f::T;
                                    match t {
                                        0 => {
                                            // RFET
                                            let k = k | f::S;
                                            let op = match s {
                                                0 => O::Rfe,
                                                1 => O::Rfue,
                                                2 => O::Rfde,
                                                4 => O::Rfwo,
                                                5 => O::Rfwu,
                                                _ => return ill(w, k),
                                            };
                                            leaf(w, k, op, Rrr, true)
                                        }
                                        1 => lf!(k, Rfi, Rrr),
                                        2 => lf!(k, Rfme, Rrr, s == 0),
                                        _ => ill(w, k),
                                    }
                                }
                                4 => lf!(k, Break, Rrr),
                                5 => lf!(k, Syscall, Rrr, s == 0 && t == 0),
                                6 => lf!(k, Rsil, Rrr),
                                7 => lf!(k, Waiti, Rrr, t == 0),
                                8 => lf!(k, Any4, Rrr),
                                9 => lf!(k, All4, Rrr),
                                10 => lf!(k, Any8, Rrr),
                                11 => lf!(k, All8, Rrr),
                                _ => ill(w, k),
                            }
                        }
                        1 => lf!(k, And, Rrr),
                        2 => lf!(k, Or, Rrr),
                        3 => lf!(k, Xor, Rrr),
                        4 => {
                            // ST1
                            let k = k | f::R;
                            match r {
                                0 => lf!(k, Ssr, Rrr, t == 0),
                                1 => lf!(k, Ssl, Rrr, t == 0),
                                2 => lf!(k, Ssa8l, Rrr, t == 0),
                                3 => lf!(k, Ssa8b, Rrr, t == 0),
                                4 => lf!(k, Ssai, Rrr, t < 2),
                                6 => lf!(k, Rer, Rrr),
                                7 => lf!(k, Wer, Rrr),
                                8 => lf!(k, Rotw, Rrr, s == 0),
                                14 => lf!(k, Nsa, Rrr),
                                15 => lf!(k, Nsau, Rrr),
                                _ => ill(w, k),
                            }
                        }
                        5 => {
                            // TLB
                            let k = k | f::R;
                            match r {
                                3 => lf!(k, Ritlb0, Rrr),
                                4 => lf!(k, Iitlb, Rrr, t == 0),
                                5 => lf!(k, Pitlb, Rrr),
                                6 => lf!(k, Witlb, Rrr),
                                7 => lf!(k, Ritlb1, Rrr),
                                11 => lf!(k, Rdtlb0, Rrr),
                                12 => lf!(k, Idtlb, Rrr, t == 0),
                                13 => lf!(k, Pdtlb, Rrr),
                                14 => lf!(k, Wdtlb, Rrr),
                                15 => lf!(k, Rdtlb1, Rrr),
                                _ => ill(w, k),
                            }
                        }
                        6 => {
                            // RT0
                            let k = k | f::S;
                            match s {
                                0 => lf!(k, Neg, Rrr),
                                1 => lf!(k, Abs, Rrr),
                                _ => ill(w, k),
                            }
                        }
                        7 => ill(w, k),
                        _ => {
                            let op = [
                                O::Add,
                                O::Addx2,
                                O::Addx4,
                                O::Addx8,
                                O::Sub,
                                O::Subx2,
                                O::Subx4,
                                O::Subx8,
                            ][(op2 - 8) as usize];
                            leaf(w, k, op, Rrr, true)
                        }
                    }
                }
                1 => {
                    // RST1
                    let k = k | f::OP2;
                    match op2 {
                        0 | 1 => lf!(k, Slli, Rrr),
                        2 | 3 => lf!(k, Srai, Rrr),
                        4 => lf!(k, Srli, Rrr),
                        6 => lf!(k, Xsr, Rsr),
                        7 => {
                            // ACCER
                            let k = k | f::R;
                            match r {
                                6 => lf!(k, Rer, Rrr),
                                7 => lf!(k, Wer, Rrr),
                                _ => ill(w, k),
                            }
                        }
                        8 => lf!(k, Src, Rrr),
                        9 => lf!(k, Srl, Rrr, s == 0),
                        10 => lf!(k, Sll, Rrr, t == 0),
                        11 => lf!(k, Sra, Rrr, s == 0),
                        12 => lf!(k, Mul16u, Rrr),
                        13 => lf!(k, Mul16s, Rrr),
                        15 => {
                            // IMP
                            let k = k | f::R;
                            match r {
                                0 => lf!(k, Lict, Rrr),
                                1 => lf!(k, Sict, Rrr),
                                2 => lf!(k, Licw, Rrr),
                                3 => lf!(k, Sicw, Rrr),
                                8 => lf!(k, Ldct, Rrr),
                                9 => lf!(k, Sdct, Rrr),
                                14 => {
                                    // RFDX
                                    let k = k | f::T;
                                    match t {
                                        0 => lf!(k, Rfdo, Rrr, s == 0),
                                        1 => lf!(k, Rfdd, Rrr, s <= 1),
                                        _ => ill(w, k),
                                    }
                                }
                                _ => ill(w, k),
                            }
                        }
                        _ => ill(w, k),
                    }
                }
                2 => {
                    // RST2
                    let k = k | f::OP2;
                    let op = match op2 {
                        0 => O::Andb,
                        1 => O::Andbc,
                        2 => O::Orb,
                        3 => O::Orbc,
                        4 => O::Xorb,
                        6 => O::Saltu,
                        7 => O::Salt,
                        8 => O::Mull,
                        10 => O::Muluh,
                        11 => O::Mulsh,
                        12 => O::Quou,
                        13 => O::Quos,
                        14 => O::Remu,
                        15 => O::Rems,
                        _ => return ill(w, k),
                    };
                    leaf(w, k, op, Rrr, true)
                }
                3 => {
                    // RST3
                    let k = k | f::OP2;
                    let (op, fmt) = match op2 {
                        0 => (O::Rsr, Rsr),
                        1 => (O::Wsr, Rsr),
                        2 => (O::Sext, Rrr),
                        3 => (O::Clamps, Rrr),
                        4 => (O::Min, Rrr),
                        5 => (O::Max, Rrr),
                        6 => (O::Minu, Rrr),
                        7 => (O::Maxu, Rrr),
                        8 => (O::Moveqz, Rrr),
                        9 => (O::Movnez, Rrr),
                        10 => (O::Movltz, Rrr),
                        11 => (O::Movgez, Rrr),
                        12 => (O::Movf, Rrr),
                        13 => (O::Movt, Rrr),
                        14 => (O::Rur, Rsr),
                        _ => (O::Wur, Rsr),
                    };
                    leaf(w, k, op, fmt, true)
                }
                4 | 5 => lf!(k, Extui, Rrr),
                8 => {
                    // LSCX
                    let k = k | f::OP2;
                    let op = match op2 {
                        0 => O::Lsx,
                        1 => O::Lsxu,
                        4 => O::Ssx,
                        5 => O::Ssxu,
                        _ => return ill(w, k),
                    };
                    leaf(w, k, op, Rrr, true)
                }
                9 => {
                    // LSC4
                    let k = k | f::OP2;
                    match op2 {
                        0 => lf!(k, L32e, Rri4),
                        4 => lf!(k, S32e, Rri4),
                        _ => ill(w, k),
                    }
                }
                10 => {
                    // FP0
                    let k = k | f::OP2;
                    let op = match op2 {
                        0 => O::AddS,
                        1 => O::SubS,
                        2 => O::MulS,
                        4 => O::MaddS,
                        5 => O::MsubS,
                        8 => O::RoundS,
                        9 => O::TruncS,
                        10 => O::FloorS,
                        11 => O::CeilS,
                        12 => O::FloatS,
                        13 => O::UfloatS,
                        14 => O::UtruncS,
                        15 => {
                            // FP1OP
                            let k = k | f::T;
                            let op = match t {
                                0 => O::MovS,
                                1 => O::AbsS,
                                4 => O::Rfr,
                                5 => O::Wfr,
                                6 => O::NegS,
                                _ => return ill(w, k),
                            };
                            return leaf(w, k, op, Rrr, true);
                        }
                        _ => return ill(w, k),
                    };
                    leaf(w, k, op, Rrr, true)
                }
                11 => {
                    // FP1
                    let k = k | f::OP2;
                    let op = match op2 {
                        1 => O::UnS,
                        2 => O::OeqS,
                        3 => O::UeqS,
                        4 => O::OltS,
                        5 => O::UltS,
                        6 => O::OleS,
                        7 => O::UleS,
                        8 => O::MoveqzS,
                        9 => O::MovnezS,
                        10 => O::MovltzS,
                        11 => O::MovgezS,
                        12 => O::MovfS,
                        13 => O::MovtS,
                        _ => return ill(w, k),
                    };
                    leaf(w, k, op, Rrr, true)
                }
                // 6, 7: CUST0/CUST1 have no handler; 12..15 reserved.
                _ => ill(w, k),
            }
        }
        1 => lf!(k, L32r, Ri16),
        2 => {
            // LSAI
            let k = k | f::R;
            let op = match r {
                0 => O::L8ui,
                1 => O::L16ui,
                2 => O::L32i,
                4 => O::S8i,
                5 => O::S16i,
                6 => O::S32i,
                7 => {
                    // CACHE
                    let k = k | f::T;
                    let op = match t {
                        0 => O::Dpfr,
                        1 => O::Dpfw,
                        2 => O::Dpfro,
                        3 => O::Dpfwo,
                        4 => O::Dhwb,
                        5 => O::Dhwbi,
                        6 => O::Dhi,
                        7 => O::Dii,
                        8 => {
                            // DCE
                            let k = k | f::OP1;
                            let op = match op1 {
                                0 => O::Dpfl,
                                2 => O::Dhu,
                                3 => O::Diu,
                                4 => O::Diwb,
                                5 => O::Diwbi,
                                _ => return ill(w, k),
                            };
                            return leaf(w, k, op, Rri4, true);
                        }
                        12 => O::Ipf,
                        13 => {
                            // ICE
                            let k = k | f::OP1;
                            let op = match op1 {
                                0 => O::Ipfl,
                                2 => O::Ihu,
                                3 => O::Iiu,
                                _ => return ill(w, k),
                            };
                            return leaf(w, k, op, Rri4, true);
                        }
                        14 => O::Ihi,
                        15 => O::Iii,
                        _ => return ill(w, k),
                    };
                    return leaf(w, k, op, Rri8, true);
                }
                9 => O::L16si,
                10 => O::Movi,
                11 => O::L32ai,
                12 => O::Addi,
                13 => O::Addmi,
                14 => O::S32c1i,
                15 => O::S32ri,
                _ => return ill(w, k),
            };
            leaf(w, k, op, Rri8, true)
        }
        3 => {
            // LSCI
            let k = k | f::R;
            let op = match r {
                0 => O::Lsi,
                4 => O::Ssi,
                8 => O::Lsiu,
                12 => O::Ssiu,
                _ => return ill(w, k),
            };
            leaf(w, k, op, Rri8, true)
        }
        4 => mac16(w, op1, op2, r, s, t),
        5 => {
            // CALLN
            let op = [O::Call0, O::Call4, O::Call8, O::Call12][n as usize];
            leaf(w, k | f::N, op, Call, true)
        }
        6 => {
            // SI
            let k = k | f::N;
            match n {
                0 => lf!(k, J, Call),
                1 => {
                    let op = [O::Beqz, O::Bnez, O::Bltz, O::Bgez][m as usize];
                    leaf(w, k | f::M, op, Bri12, true)
                }
                2 => {
                    let op = [O::Beqi, O::Bnei, O::Blti, O::Bgei][m as usize];
                    leaf(w, k | f::M, op, Bri8, true)
                }
                _ => {
                    // BI1
                    let k = k | f::M;
                    match m {
                        0 => lf!(k, Entry, Bri12),
                        1 => {
                            // B1
                            let k = k | f::R;
                            let op = match r {
                                0 => O::Bf,
                                1 => O::Bt,
                                8 => O::Loop,
                                9 => O::Loopnez,
                                10 => O::Loopgtz,
                                _ => return ill(w, k),
                            };
                            leaf(w, k, op, Bri8, true)
                        }
                        2 => lf!(k, Bltui, Bri8),
                        _ => lf!(k, Bgeui, Bri8),
                    }
                }
            }
        }
        7 => {
            // B
            let op = [
                O::Bnone,
                O::Beq,
                O::Blt,
                O::Bltu,
                O::Ball,
                O::Bbc,
                O::Bbci,
                O::Bbci,
                O::Bany,
                O::Bne,
                O::Bge,
                O::Bgeu,
                O::Bnall,
                O::Bbs,
                O::Bbsi,
                O::Bbsi,
            ][r as usize];
            leaf(w, k | f::R, op, Rri8, true)
        }
        8 => lf!(k, L32iN, Rrrn),
        9 => lf!(k, S32iN, Rrrn),
        10 => lf!(k, AddN, Rrrn),
        11 => lf!(k, AddiN, Rrrn),
        12 => {
            // ST2
            let k = k | f::T;
            match t {
                0..=7 => lf!(k, MoviN, Ri7),
                8..=11 => lf!(k, BeqzN, Ri6),
                _ => lf!(k, BnezN, Ri6),
            }
        }
        13 => {
            // ST3
            let k = k | f::R;
            match r {
                0 => lf!(k, MovN, Rrrn),
                15 => {
                    // S3
                    let k = k | f::T;
                    let op = match t {
                        0 => O::RetN,
                        1 => O::RetwN,
                        2 => O::BreakN,
                        3 => O::NopN,
                        6 => O::IllN,
                        _ => return ill(w, k),
                    };
                    leaf(w, k, op, Rrrn, true)
                }
                _ => ill(w, k),
            }
        }
        _ => ill(w, k),
    }
}

/// MAC16 (`op0 == 4`): `_decode_MAC16` reads op1, then dispatches on op2.
#[inline]
fn mac16(w: [u8; 3], op1: u8, op2: u8, r: u8, s: u8, t: u8) -> Insn {
    let k = f::OP0 | f::OP1 | f::OP2;
    let half = (op1 & 3) as u16;
    match op2 {
        // MACID, MACCD, MACIA, MACCA: compound load + MULA.
        0 | 1 | 4 | 5 => {
            let da = op2 >= 4;
            let dec = op2 & 1 == 1;
            let idx = (da as u16 ^ 1) * 8 + half * 2 + dec as u16;
            let op = mac_compound_opcode(idx);
            let valid = (8..=11).contains(&op1) && r < 8 && (da || t == 0 || t == 4);
            leaf(w, k, op, Format::Rrr, valid)
        }
        // MACDD, MACAD, MACDA, MACAA: arithmetic.
        2 | 3 | 6 | 7 => {
            // kind index in AA, AD, DA, DD order
            let kind: u16 = match op2 {
                7 => 0,
                3 => 1,
                6 => 2,
                _ => 3,
            };
            let a_left = kind <= 1;
            let a_right = kind == 0 || kind == 2;
            let mut valid = op1 >= 4 || kind == 0;
            if a_left {
                valid &= r == 0;
            } else {
                valid &= s == 0 && (r == 0 || r == 4);
            }
            if !a_right {
                valid &= t == 0 || t == 4;
            }
            let idx = kind * 16 + ((op1 >> 2) as u16) * 4 + half;
            leaf(w, k, mac_arith_opcode(idx), Format::Rrr, valid)
        }
        8 => leaf(w, k, O::Ldinc, Format::Rrr, op1 == 0 && r < 4 && t == 0),
        9 => leaf(w, k, O::Lddec, Format::Rrr, op1 == 0 && r < 4 && t == 0),
        _ => ill(w, k),
    }
}

/// MAC16 arithmetic opcodes in (kind AA/AD/DA/DD, op UMUL/MUL/MULA/MULS,
/// half LL/HL/LH/HH) order.
pub(crate) const MAC_ARITH: [O; 64] = {
    let mut out = [O::Ill; 64];
    let base = O::UmulAaLl as usize;
    let mut i = 0;
    while i < 64 {
        out[i] = O::ALL[base + i];
        i += 1;
    }
    out
};

/// MAC16 compound opcodes in (kind DA/DD, half, LDINC/LDDEC) order.
pub(crate) const MAC_COMPOUND: [O; 16] = {
    let mut out = [O::Ill; 16];
    let base = O::MulaDaLlLdinc as usize;
    let mut i = 0;
    while i < 16 {
        out[i] = O::ALL[base + i];
        i += 1;
    }
    out
};

#[inline(always)]
fn mac_arith_opcode(idx: u16) -> O {
    MAC_ARITH[idx as usize & 63]
}

#[inline(always)]
fn mac_compound_opcode(idx: u16) -> O {
    MAC_COMPOUND[idx as usize & 15]
}
