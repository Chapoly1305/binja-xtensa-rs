//! [`Insn`], [`Format`], decoded fields and the helpers the reference
//! `Instruction` class exposes to disassembly and lifting.

use crate::decode::{MAC_ARITH, MAC_COMPOUND};
use crate::opcode::Opcode;
use crate::regs;

/// The reference decoder's `InstructionType`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Format {
    Rrr = 1,
    Rsr = 2,
    Callx = 3,
    Rri4 = 4,
    Rri8 = 5,
    Ri16 = 6,
    Call = 7,
    Bri8 = 8,
    Bri12 = 9,
    Rrrn = 10,
    Ri7 = 11,
    Ri6 = 12,
}

impl Format {
    /// The Python enum member name (`"RRR"`, `"RI16"`, ...).
    pub const fn name(self) -> &'static str {
        match self {
            Format::Rrr => "RRR",
            Format::Rsr => "RSR",
            Format::Callx => "CALLX",
            Format::Rri4 => "RRI4",
            Format::Rri8 => "RRI8",
            Format::Ri16 => "RI16",
            Format::Call => "CALL",
            Format::Bri8 => "BRI8",
            Format::Bri12 => "BRI12",
            Format::Rrrn => "RRRN",
            Format::Ri7 => "RI7",
            Format::Ri6 => "RI6",
        }
    }
}

/// Decoded-field identifiers, in the oracle's print order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Field {
    Op0,
    Op1,
    Op2,
    R,
    S,
    Sr,
    T,
    N,
    M,
    I,
    Z,
    Imm4,
    Imm6,
    Imm7,
    Imm8,
    Imm12,
    Imm16,
    Offset,
}

impl Field {
    /// All fields in the oracle's print order.
    pub const ALL: [Field; 18] = [
        Field::Op0,
        Field::Op1,
        Field::Op2,
        Field::R,
        Field::S,
        Field::Sr,
        Field::T,
        Field::N,
        Field::M,
        Field::I,
        Field::Z,
        Field::Imm4,
        Field::Imm6,
        Field::Imm7,
        Field::Imm8,
        Field::Imm12,
        Field::Imm16,
        Field::Offset,
    ];

    /// The Python attribute name.
    pub const fn name(self) -> &'static str {
        match self {
            Field::Op0 => "op0",
            Field::Op1 => "op1",
            Field::Op2 => "op2",
            Field::R => "r",
            Field::S => "s",
            Field::Sr => "sr",
            Field::T => "t",
            Field::N => "n",
            Field::M => "m",
            Field::I => "i",
            Field::Z => "z",
            Field::Imm4 => "imm4",
            Field::Imm6 => "imm6",
            Field::Imm7 => "imm7",
            Field::Imm8 => "imm8",
            Field::Imm12 => "imm12",
            Field::Imm16 => "imm16",
            Field::Offset => "offset",
        }
    }
}

/// Bit masks for the field-presence set.
pub(crate) mod field {
    pub const OP0: u32 = 1 << 0;
    pub const OP1: u32 = 1 << 1;
    pub const OP2: u32 = 1 << 2;
    pub const R: u32 = 1 << 3;
    pub const S: u32 = 1 << 4;
    pub const SR: u32 = 1 << 5;
    pub const T: u32 = 1 << 6;
    pub const N: u32 = 1 << 7;
    pub const M: u32 = 1 << 8;
    pub const I: u32 = 1 << 9;
    pub const Z: u32 = 1 << 10;
    pub const IMM4: u32 = 1 << 11;
    pub const IMM6: u32 = 1 << 12;
    pub const IMM7: u32 = 1 << 13;
    pub const IMM8: u32 = 1 << 14;
    pub const IMM12: u32 = 1 << 15;
    pub const IMM16: u32 = 1 << 16;
    pub const OFFSET: u32 = 1 << 17;
}

/// All decoded fields at once, `None` exactly where the reference leaves the
/// attribute `None`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Fields {
    pub op0: Option<u8>,
    pub op1: Option<u8>,
    pub op2: Option<u8>,
    pub r: Option<u8>,
    pub s: Option<u8>,
    pub sr: Option<u8>,
    pub t: Option<u8>,
    pub n: Option<u8>,
    pub m: Option<u8>,
    pub i: Option<u8>,
    pub z: Option<u8>,
    pub imm4: Option<u8>,
    pub imm6: Option<u8>,
    pub imm7: Option<u8>,
    pub imm8: Option<u8>,
    pub imm12: Option<u16>,
    pub imm16: Option<u16>,
    pub offset: Option<u32>,
}

/// MAC16 operand kind (`mac_kind`): which side reads an address register
/// (`A`) or a MAC16 data register (`D`, m0..m3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MacKind {
    Aa,
    Ad,
    Da,
    Dd,
}

impl MacKind {
    /// The Python string (`"AA"`, `"AD"`, `"DA"`, `"DD"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            MacKind::Aa => "AA",
            MacKind::Ad => "AD",
            MacKind::Da => "DA",
            MacKind::Dd => "DD",
        }
    }
}

/// MAC16 operation (`mac_operation`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MacOperation {
    Umul,
    Mul,
    Mula,
    Muls,
}

impl MacOperation {
    /// The Python string (`"UMUL"`, `"MUL"`, `"MULA"`, `"MULS"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            MacOperation::Umul => "UMUL",
            MacOperation::Mul => "MUL",
            MacOperation::Mula => "MULA",
            MacOperation::Muls => "MULS",
        }
    }
}

/// A register named by a MAC16 attribute: `a<n>` (address register) or
/// `m<n>` (the Python strings use `m2 + (t >> 2)`, so `m4`/`m5` occur for
/// invalid encodings).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MacReg {
    A(u8),
    M(u8),
}

impl MacReg {
    /// The Python string, e.g. `"a5"` or `"m2"`.
    pub fn name(self) -> &'static str {
        match self {
            MacReg::A(n) => regs::ar_name(n),
            MacReg::M(n) => regs::mr_name(n),
        }
    }
}

/// A decoded instruction. `Copy`, 12 bytes, no heap.
///
/// The public fields mirror `mnem`, `length`, `valid` and `instruction_type`
/// of the reference; the decoded bit fields are accessor methods returning
/// `Option` (`None` exactly where the reference attribute is `None`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Insn {
    /// The mnemonic (`Opcode::mnemonic()` is the reference `mnem` string).
    pub opcode: Opcode,
    /// Instruction length in bytes (2 or 3).
    pub len: u8,
    /// The reference `valid` flag (encoding constraints satisfied).
    pub valid: bool,
    /// The reference `instruction_type`; `None` for a reserved slot
    /// (`opcode == Opcode::Ill`, `valid == false`).
    pub format: Option<Format>,
    present: u32,
    raw: [u8; 3],
}

#[inline(always)]
const fn sign_extend(value: i64, bits: u32) -> i64 {
    let sign_bit = 1i64 << (bits - 1);
    (value & (sign_bit - 1)) - (value & sign_bit)
}

const B4CONST: [i64; 16] = [-1, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 16, 32, 64, 128, 256];
const B4CONSTU: [i64; 16] = [
    32768, 65536, 2, 3, 4, 5, 6, 7, 8, 10, 12, 16, 32, 64, 128, 256,
];

macro_rules! field_getter {
    ($(#[$doc:meta])* $name:ident, $ty:ty, $bit:ident, |$w:ident| $e:expr) => {
        $(#[$doc])*
        #[inline(always)]
        pub const fn $name(&self) -> Option<$ty> {
            if self.present & field::$bit != 0 {
                let $w = self.raw;
                Some($e)
            } else {
                None
            }
        }
    };
}

impl Insn {
    #[inline(always)]
    pub(crate) const fn from_parts(
        opcode: Opcode,
        len: u8,
        valid: bool,
        format: Option<Format>,
        present: u32,
        raw: [u8; 3],
    ) -> Self {
        Insn {
            opcode,
            len,
            valid,
            format,
            present,
            raw,
        }
    }

    #[inline(always)]
    pub(crate) const fn present_mask(&self) -> u32 {
        self.present
    }

    /// The reference `mnem` string.
    #[inline]
    pub const fn mnemonic(&self) -> &'static str {
        self.opcode.mnemonic()
    }

    /// The first three input bytes (zero-padded for short inputs).
    #[inline]
    pub const fn raw(&self) -> [u8; 3] {
        self.raw
    }

    /// Whether the reference decoder set `field`.
    #[inline]
    pub const fn has(&self, f: Field) -> bool {
        self.present & (1 << f as u32) != 0
    }

    field_getter!(op0, u8, OP0, |w| w[0] & 0xf);
    field_getter!(op1, u8, OP1, |w| w[2] & 0xf);
    field_getter!(op2, u8, OP2, |w| w[2] >> 4);
    field_getter!(r, u8, R, |w| w[1] >> 4);
    field_getter!(s, u8, S, |w| w[1] & 0xf);
    field_getter!(sr, u8, SR, |w| w[1]);
    field_getter!(t, u8, T, |w| w[0] >> 4);
    field_getter!(n, u8, N, |w| (w[0] >> 4) & 3);
    field_getter!(m, u8, M, |w| (w[0] >> 6) & 3);
    field_getter!(i, u8, I, |w| (w[0] >> 7) & 1);
    field_getter!(z, u8, Z, |w| (w[0] >> 6) & 1);
    field_getter!(imm4, u8, IMM4, |w| w[2] >> 4);
    field_getter!(imm6, u8, IMM6, |w| (((w[0] >> 4) & 3) << 4) + (w[1] >> 4));
    field_getter!(imm7, u8, IMM7, |w| (((w[0] >> 4) & 7) << 4) + (w[1] >> 4));
    field_getter!(imm8, u8, IMM8, |w| w[2]);
    field_getter!(imm12, u16, IMM12, |w| ((w[2] as u16) << 4)
        + (w[1] >> 4) as u16);
    field_getter!(imm16, u16, IMM16, |w| ((w[2] as u16) << 8) + w[1] as u16);
    field_getter!(offset, u32, OFFSET, |w| ((w[2] as u32) << 10)
        + ((w[1] as u32) << 2)
        + ((w[0] >> 6) & 3) as u32);

    /// Value of `f`, widened to `u32`.
    pub const fn field(&self, f: Field) -> Option<u32> {
        macro_rules! w {
            ($e:expr) => {
                match $e {
                    Some(v) => Some(v as u32),
                    None => None,
                }
            };
        }
        match f {
            Field::Op0 => w!(self.op0()),
            Field::Op1 => w!(self.op1()),
            Field::Op2 => w!(self.op2()),
            Field::R => w!(self.r()),
            Field::S => w!(self.s()),
            Field::Sr => w!(self.sr()),
            Field::T => w!(self.t()),
            Field::N => w!(self.n()),
            Field::M => w!(self.m()),
            Field::I => w!(self.i()),
            Field::Z => w!(self.z()),
            Field::Imm4 => w!(self.imm4()),
            Field::Imm6 => w!(self.imm6()),
            Field::Imm7 => w!(self.imm7()),
            Field::Imm8 => w!(self.imm8()),
            Field::Imm12 => w!(self.imm12()),
            Field::Imm16 => w!(self.imm16()),
            Field::Offset => self.offset(),
        }
    }

    /// All decoded fields as a struct of `Option`s.
    pub const fn fields(&self) -> Fields {
        Fields {
            op0: self.op0(),
            op1: self.op1(),
            op2: self.op2(),
            r: self.r(),
            s: self.s(),
            sr: self.sr(),
            t: self.t(),
            n: self.n(),
            m: self.m(),
            i: self.i(),
            z: self.z(),
            imm4: self.imm4(),
            imm6: self.imm6(),
            imm7: self.imm7(),
            imm8: self.imm8(),
            imm12: self.imm12(),
            imm16: self.imm16(),
            offset: self.offset(),
        }
    }

    // ---- immediate helpers (reference `Instruction` methods) ----

    /// `extui_shiftimm()`: `((op1 & 1) << 4) + s` for EXTUI, else `None`.
    pub const fn extui_shiftimm(&self) -> Option<i64> {
        match (self.opcode, self.op1(), self.s()) {
            (Opcode::Extui, Some(op1), Some(s)) => Some((((op1 & 1) << 4) + s) as i64),
            _ => None,
        }
    }

    /// `simm6()`: `sign_extend(imm6, 8)` (sic: 8, so never negative).
    pub const fn simm6(&self) -> Option<i64> {
        match self.imm6() {
            Some(v) => Some(sign_extend(v as i64, 8)),
            None => None,
        }
    }

    /// `simm8()`: `sign_extend(imm8, 8)`.
    pub const fn simm8(&self) -> Option<i64> {
        match self.imm8() {
            Some(v) => Some(sign_extend(v as i64, 8)),
            None => None,
        }
    }

    /// `simm12()`: `sign_extend(imm12, 12)`.
    pub const fn simm12(&self) -> Option<i64> {
        match self.imm12() {
            Some(v) => Some(sign_extend(v as i64, 12)),
            None => None,
        }
    }

    /// `rotw_simm4()`: `sign_extend(t, 4)`.
    pub const fn rotw_simm4(&self) -> Option<i64> {
        match self.t() {
            Some(v) => Some(sign_extend(v as i64, 4)),
            None => None,
        }
    }

    /// `b4const()`: B4CONST(r) for BEQI/BNEI/BLTI/BGEI, else `None` (the
    /// reference raises `KeyError`).
    pub const fn b4const(&self) -> Option<i64> {
        match (self.opcode, self.r()) {
            (Opcode::Beqi | Opcode::Bgei | Opcode::Blti | Opcode::Bnei, Some(r)) => {
                Some(B4CONST[r as usize])
            }
            _ => None,
        }
    }

    /// `b4constu()`: B4CONSTU(r) for BLTUI/BGEUI, else `None`.
    pub const fn b4constu(&self) -> Option<i64> {
        match (self.opcode, self.r()) {
            (Opcode::Bgeui | Opcode::Bltui, Some(r)) => Some(B4CONSTU[r as usize]),
            _ => None,
        }
    }

    /// `target_offset(addr)`: the branch/call/jump target for the opcodes in
    /// the reference `_target_offset_map`, else `None`. Arbitrary precision
    /// like Python (no 32-bit wrap).
    pub const fn target_offset(&self, addr: u32) -> Option<i64> {
        use Opcode::*;
        let a = addr as i64;
        match self.opcode {
            Ball | Bany | Bbc | Bbci | Bbs | Bbsi | Beq | Beqi | Bf | Bge | Bgei | Bgeu | Bgeui
            | Blt | Blti | Bltu | Bltui | Bnall | Bne | Bnei | Bnone | Bt => match self.simm8() {
                Some(v) => Some(a + 4 + v),
                None => None,
            },
            Beqz | Bgez | Bltz | Bnez => match self.simm12() {
                Some(v) => Some(a + 4 + v),
                None => None,
            },
            BeqzN | BnezN => match self.imm6() {
                Some(v) => Some(a + 4 + v as i64),
                None => None,
            },
            Call0 | Call4 | Call8 | Call12 => match self.offset() {
                Some(o) => Some((a & 0xffff_fffc) + (sign_extend(o as i64, 18) << 2) + 4),
                None => None,
            },
            J => match self.offset() {
                Some(o) => Some(a + 4 + sign_extend(o as i64, 18)),
                None => None,
            },
            _ => None,
        }
    }

    /// `mem_offset(addr)`: the L32R literal address, else `None`.
    pub const fn mem_offset(&self, addr: u32) -> Option<i64> {
        match (self.opcode, self.imm16()) {
            (Opcode::L32r, Some(imm16)) => {
                let enc = sign_extend(imm16 as i64 | 0xFFFF_0000, 32) << 2;
                Some((enc + addr as i64 + 3) & 0xFFFF_FFFC)
            }
            _ => None,
        }
    }

    /// The bound `inline0` method, if the reference attaches one to this
    /// opcode. The reference lambdas ignore the address.
    pub const fn inline0(&self) -> Option<i64> {
        use Opcode::*;
        let w = self.raw;
        let t = (w[0] >> 4) as i64;
        let s = (w[1] & 0xf) as i64;
        let r = (w[1] >> 4) as i64;
        let op2 = (w[2] >> 4) as i64;
        let imm8 = w[2] as i64;
        Some(match self.opcode {
            L32iN | S32iN => r << 2,
            AddiN => {
                if t != 0 {
                    t
                } else {
                    -1
                }
            }
            Ssai => s + ((t & 1) << 4),
            Slli => 32 - (t + ((op2 & 1) << 4)),
            Srai => s + ((op2 & 1) << 4),
            Sext => t + 7,
            L32e | S32e => (r << 2) - 64,
            L16ui | S16i | L16si => imm8 << 1,
            L32i | S32i | L32ai | S32ri | Lsi | Ssi | Lsiu | Ssiu => imm8 << 2,
            Movi => sign_extend((s << 8) + imm8, 12),
            Entry => match self.imm12() {
                Some(v) => (v as i64) << 3,
                None => return None,
            },
            Bbci | Bbsi => t + ((r & 1) << 4),
            MoviN => match self.imm7() {
                Some(v) => {
                    let v = v as i64;
                    if (v >> 5) == 3 {
                        sign_extend(v, 7)
                    } else {
                        v
                    }
                }
                None => return None,
            },
            _ => return None,
        })
    }

    /// The bound `inline1` method (EXTUI only: `op2 + 1`).
    pub const fn inline1(&self) -> Option<i64> {
        match (self.opcode, self.op2()) {
            (Opcode::Extui, Some(op2)) => Some(op2 as i64 + 1),
            _ => None,
        }
    }

    /// `inline<n>(addr)`; `None` if the reference has no such bound method.
    pub const fn inline(&self, n: u8, _addr: u32) -> Option<i64> {
        match n {
            0 => self.inline0(),
            1 => self.inline1(),
            _ => None,
        }
    }

    // ---- special / user registers ----

    /// `get_sr_name()` source: the `sr` field for RSR/WSR/XSR, else `None`.
    pub const fn special_reg(&self) -> Option<u8> {
        match self.opcode {
            Opcode::Rsr | Opcode::Wsr | Opcode::Xsr => self.sr(),
            _ => None,
        }
    }

    /// `get_ur_name()` source: the `sr` field for RUR/WUR, else `None`.
    pub const fn user_reg(&self) -> Option<u8> {
        match self.opcode {
            Opcode::Rur | Opcode::Wur => self.sr(),
            _ => None,
        }
    }

    /// `get_sr_name()` when the register is in the table (otherwise the
    /// reference prints `str(sr)`; see [`Insn::special_reg`]).
    pub fn special_reg_name(&self) -> Option<&'static str> {
        self.special_reg()
            .and_then(regs::special_reg)
            .map(|(name, _)| name)
    }

    /// `get_ur_name()` when the register is in the table.
    pub fn user_reg_name(&self) -> Option<&'static str> {
        self.user_reg()
            .and_then(regs::user_reg)
            .map(|(name, _)| name)
    }

    // ---- MAC16 attributes (set only by the MAC16 arithmetic/compound paths) ----

    const fn mac_arith_index(&self) -> Option<usize> {
        let base = MAC_ARITH[0] as usize;
        let o = self.opcode as usize;
        if o >= base && o < base + 64 {
            Some(o - base)
        } else {
            None
        }
    }

    const fn mac_compound_index(&self) -> Option<usize> {
        let base = MAC_COMPOUND[0] as usize;
        let o = self.opcode as usize;
        if o >= base && o < base + 16 {
            Some(o - base)
        } else {
            None
        }
    }

    /// `mac_kind`: set for MAC16 arithmetic and compound forms.
    pub const fn mac_kind(&self) -> Option<MacKind> {
        const KINDS: [MacKind; 4] = [MacKind::Aa, MacKind::Ad, MacKind::Da, MacKind::Dd];
        if let Some(i) = self.mac_arith_index() {
            return Some(KINDS[i / 16]);
        }
        if let Some(i) = self.mac_compound_index() {
            return Some(if i < 8 { MacKind::Da } else { MacKind::Dd });
        }
        None
    }

    /// `mac_operation`: `MULA` for the compound forms.
    pub const fn mac_operation(&self) -> Option<MacOperation> {
        const OPS: [MacOperation; 4] = [
            MacOperation::Umul,
            MacOperation::Mul,
            MacOperation::Mula,
            MacOperation::Muls,
        ];
        if let Some(i) = self.mac_arith_index() {
            return Some(OPS[(i / 4) % 4]);
        }
        if self.mac_compound_index().is_some() {
            return Some(MacOperation::Mula);
        }
        None
    }

    /// `mac_half`: `op1 & 3` (0=LL, 1=HL, 2=LH, 3=HH).
    pub const fn mac_half(&self) -> Option<u8> {
        if self.mac_kind().is_none() {
            return None;
        }
        match self.op1() {
            Some(op1) => Some(op1 & 3),
            None => None,
        }
    }

    /// `mac_load_delta`: +4 (LDINC) / -4 (LDDEC), compound forms only.
    pub const fn mac_load_delta(&self) -> Option<i8> {
        match self.mac_compound_index() {
            Some(i) => Some(if i % 2 == 0 { 4 } else { -4 }),
            None => None,
        }
    }

    /// `mac_left`.
    pub const fn mac_left(&self) -> Option<MacReg> {
        let w = self.raw;
        let s = w[1] & 0xf;
        let r = w[1] >> 4;
        match self.mac_kind() {
            None => None,
            Some(MacKind::Aa | MacKind::Ad) if self.mac_compound_index().is_none() => {
                Some(MacReg::A(s))
            }
            Some(_) => Some(MacReg::M(r >> 2)),
        }
    }

    /// `mac_right`.
    pub const fn mac_right(&self) -> Option<MacReg> {
        let t = self.raw[0] >> 4;
        match self.mac_kind() {
            None => None,
            Some(MacKind::Aa | MacKind::Da) => Some(MacReg::A(t)),
            Some(_) => Some(MacReg::M(2 + (t >> 2))),
        }
    }

    /// `mac_base`: compound forms only (`a<s>`).
    pub const fn mac_base(&self) -> Option<MacReg> {
        match self.mac_compound_index() {
            Some(_) => Some(MacReg::A(self.raw[1] & 0xf)),
            None => None,
        }
    }

    /// `mac_destination`: compound forms only (`m<r & 3>`).
    pub const fn mac_destination(&self) -> Option<MacReg> {
        match self.mac_compound_index() {
            Some(_) => Some(MacReg::M((self.raw[1] >> 4) & 3)),
            None => None,
        }
    }
}
