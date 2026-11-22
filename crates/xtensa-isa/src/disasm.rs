//! Disassembly tokens, a transcription of the reference `disassembly.py`.

use crate::insn::{Format, Insn};
use crate::opcode::Opcode;
use crate::regs;

/// Binary Ninja `InstructionTextTokenType` subset used by the reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TokenKind {
    Text,
    Instruction,
    OperandSeparator,
    Register,
    Integer,
    PossibleAddress,
}

impl TokenKind {
    /// The short tag the oracle prints (`text`, `insn`, `sep`, `reg`, `int`,
    /// `addr`).
    pub const fn tag(self) -> &'static str {
        match self {
            TokenKind::Text => "text",
            TokenKind::Instruction => "insn",
            TokenKind::OperandSeparator => "sep",
            TokenKind::Register => "reg",
            TokenKind::Integer => "int",
            TokenKind::PossibleAddress => "addr",
        }
    }
}

/// Capacity of [`TokenText`]; the longest text the reference emits is
/// `"unimplemented_disass"` (20 bytes).
pub const TOKEN_TEXT_CAP: usize = 23;

/// A small inline ASCII string (no heap). Text longer than
/// [`TOKEN_TEXT_CAP`] is truncated (never happens for decoder output).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TokenText {
    len: u8,
    buf: [u8; TOKEN_TEXT_CAP],
}

impl TokenText {
    /// An empty string.
    pub const fn new() -> Self {
        TokenText {
            len: 0,
            buf: [0; TOKEN_TEXT_CAP],
        }
    }

    /// Build from `s` (ASCII expected; truncated at the capacity).
    pub fn from_str_lossy(s: &str) -> Self {
        let mut t = Self::new();
        t.push_str(s);
        t
    }

    fn push_str(&mut self, s: &str) {
        for &b in s.as_bytes() {
            self.push(b);
        }
    }

    fn push(&mut self, b: u8) {
        if (self.len as usize) < TOKEN_TEXT_CAP && b.is_ascii() {
            self.buf[self.len as usize] = b;
            self.len += 1;
        }
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len as usize]).unwrap_or("")
    }

    fn push_dec(&mut self, v: i64) {
        if v < 0 {
            self.push(b'-');
        }
        self.push_digits(v.unsigned_abs(), 10);
    }

    fn push_digits(&mut self, mut u: u64, base: u64) {
        let mut tmp = [0u8; 20];
        let mut i = tmp.len();
        loop {
            i -= 1;
            tmp[i] = b"0123456789abcdef"[(u % base) as usize];
            u /= base;
            if u == 0 {
                break;
            }
        }
        for &b in &tmp[i..] {
            self.push(b);
        }
    }
}

impl Default for TokenText {
    fn default() -> Self {
        Self::new()
    }
}

impl core::ops::Deref for TokenText {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl core::fmt::Debug for TokenText {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self.as_str(), f)
    }
}

impl core::fmt::Display for TokenText {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One `InstructionTextToken`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Token {
    pub kind: TokenKind,
    pub text: TokenText,
    /// The token value (Python int; 0 for non-numeric tokens).
    pub value: i64,
    /// The token size (0 for non-numeric tokens).
    pub size: u8,
}

impl Token {
    fn plain(kind: TokenKind, text: &str) -> Self {
        Token {
            kind,
            text: TokenText::from_str_lossy(text),
            value: 0,
            size: 0,
        }
    }

    fn int(v: i64, size: u8) -> Self {
        let mut text = TokenText::new();
        text.push_dec(v);
        Token {
            kind: TokenKind::Integer,
            text,
            value: v,
            size,
        }
    }

    /// `hex(addr)[2:]`, including its Python quirk for negatives (`"x5"`).
    fn addr(v: i64) -> Self {
        let mut text = TokenText::new();
        if v < 0 {
            text.push(b'x');
        }
        text.push_digits(v.unsigned_abs(), 16);
        Token {
            kind: TokenKind::PossibleAddress,
            text,
            value: v,
            size: 4,
        }
    }
}

/// Operand renderers (the reference `_disassembly_fmts` keys plus the
/// per-instruction `inline` lambdas).
#[derive(Clone, Copy)]
enum Opd {
    Ar,
    As,
    At,
    Fr,
    Fs,
    Ft,
    BoolT,
    BoolS,
    BoolR,
    /// `s`/`t` as an imm8 token.
    S,
    T,
    Imm4,
    Imm8,
    Simm8,
    Simm8S8,
    RotwSimm4,
    Target,
    Mem,
    B4const,
    B4constu,
    /// `insn.inline0` as an imm8 / imm32 token.
    Inl0x8,
    Inl0x32,
    /// EXTUI: `extui_shiftimm()` / `inline1` as imm8.
    ExtuiShift,
    Inl1x8,
    /// CLAMPS: `t + 7` as imm8.
    ClampsImm,
    /// S32E: `(r << 2) - 64` as imm8.
    S32eImm,
    /// LDINC/LDDEC: `m<r>`.
    MacMr,
    MacDest,
    MacBase,
    MacLeft,
    MacRight,
}

use Opd::*;

/// The operand list, or `None` when the reference prints
/// `"unimplemented_disass"` (no renderer and no type fallback).
fn operands(insn: &Insn) -> Option<&'static [Opd]> {
    use Opcode::*;
    if insn.mac_load_delta().is_some() {
        return Some(&[MacDest, MacBase, MacLeft, MacRight]);
    }
    if insn.mac_kind().is_some() {
        return Some(&[MacLeft, MacRight]);
    }
    let list: &'static [Opd] = match insn.opcode {
        Loop | Loopgtz | Loopnez => &[As, Imm8],
        Lddec | Ldinc => &[MacMr, As],
        Clamps => &[Ar, As, ClampsImm],
        Sext => &[Ar, As, Inl0x8],
        Nsa | Nsau => &[At, As],
        All4 | All8 | Any4 | Any8 => &[BoolT, BoolS],
        Andb | Andbc | Orb | Orbc | Xorb => &[BoolR, BoolS, BoolT],
        Bf | Bt => &[BoolS, Target],
        Movf | Movt => &[Ar, As, BoolT],
        AbsS | NegS | MovS => &[Fr, Fs],
        AddS | SubS | MaddS | MsubS | MulS => &[Fr, Fs, Ft],
        CeilS | FloorS | TruncS | UtruncS | RoundS => &[Ar, Fs, T],
        FloatS | UfloatS => &[Fr, As, T],
        MovnezS | MoveqzS | MovgezS | MovltzS => &[Fr, Fs, At],
        MovtS | MovfS => &[Fr, Fs, BoolT],
        Rfr => &[Ar, Fs],
        Wfr => &[Fr, As],
        OeqS | OleS | OltS | UeqS | UltS | UleS | UnS => &[BoolR, Fs, Ft],
        Lsi | Lsiu | Ssi | Ssiu => &[Ft, As, Inl0x32],
        Lsx | Lsxu | Ssx | Ssxu => &[Fr, As, At],
        L32ai | S32ri => &[At, As, Inl0x32],
        S32c1i => &[At, As, Imm8],
        Excw | Ill | IllN | Rfde | Rfe | Rfue | Syscall | Retw | RetwN | Rfwo | Rfwu | Rfme
        | Rfdo | Rfdd | Dsync | Esync | Extw | Isync | Memw | Nop | NopN | Ret | RetN | Rsync => {
            &[]
        }
        Rfi | Waiti => &[S],
        Rsil => &[At, S],
        Ihi | Iii | Ipf => &[As, Imm8],
        Lict | Licw | Sict | Sicw => &[At, As],
        Ihu | Iiu | Ipfl => &[As, Imm4],
        Dhi | Dhwb | Dhwbi | Dii | Dpfr | Dpfro | Dpfw | Dpfwo => &[As, Imm8],
        Diwb | Diwbi => &[As, Imm4],
        Ldct | Sdct => &[At, As],
        Dhu | Diu | Dpfl => &[As, Imm4],
        Idtlb | Iitlb => &[As],
        Pdtlb | Pitlb | Rdtlb0 | Rdtlb1 | Ritlb0 | Ritlb1 | Wdtlb | Witlb => &[At, As],
        Call0 | Call4 | Call8 | Call12 | J => &[Target],
        Callx0 | Callx4 | Callx8 | Callx12 | Jx => &[As],
        Entry => &[As, Inl0x32],
        Rotw => &[RotwSimm4],
        Movsp => &[At, As],
        L32e => &[At, As, Inl0x8],
        S32e => &[At, As, S32eImm],
        Break => &[S, T],
        BreakN => &[S],
        Abs | Neg => &[Ar, At],
        AddiN => &[Ar, As, Inl0x32],
        Addmi => &[At, As, Simm8S8],
        Ball | Bany | Bbc | Bbs | Beq | Bge | Bgeu | Blt | Bltu | Bnall | Bne | Bnone => {
            &[As, At, Target]
        }
        Bbci | Bbsi => &[As, Inl0x8, Target],
        Beqi | Bgei | Blti | Bnei => &[As, B4const, Target],
        Bgeui | Bltui => &[As, B4constu, Target],
        Beqz | Bgez | Bltz | Bnez | BeqzN | BnezN => &[As, Target],
        Extui => &[Ar, At, ExtuiShift, Inl1x8],
        L8ui | S8i => &[At, As, Imm8],
        L16si | L16ui | L32i | L32iN | S16i | S32i | S32iN => &[At, As, Inl0x32],
        L32r => &[At, Mem],
        Movi => &[At, Inl0x32],
        MoviN => &[As, Inl0x32],
        MovN => &[At, As],
        Sll => &[Ar, As],
        Slli => &[Ar, As, Inl0x8],
        Sra | Srl => &[Ar, At],
        Srai => &[Ar, At, Inl0x8],
        Srli => &[Ar, At, S],
        Ssa8b | Ssa8l | Ssl | Ssr => &[As],
        Ssai => &[Inl0x8],
        Wer | Rer => &[At, As],
        _ => match insn.format {
            Some(Format::Rrr) | Some(Format::Rrrn) => &[Ar, As, At],
            Some(Format::Rri8) => &[At, As, Simm8],
            _ => return None,
        },
    };
    Some(list)
}

fn operand_token(insn: &Insn, opd: Opd, addr: u32) -> Token {
    let reg = |name: &str| Token::plain(TokenKind::Register, name);
    let g = |v: Option<u8>| v.unwrap_or(0);
    let gi = |v: Option<i64>| v.unwrap_or(0);
    match opd {
        Ar => reg(regs::ar_name(g(insn.r()))),
        As => reg(regs::ar_name(g(insn.s()))),
        At => reg(regs::ar_name(g(insn.t()))),
        Fr => reg(regs::fr_name(g(insn.r()))),
        Fs => reg(regs::fr_name(g(insn.s()))),
        Ft => reg(regs::fr_name(g(insn.t()))),
        BoolT => reg(regs::br_name(g(insn.t()))),
        BoolS => reg(regs::br_name(g(insn.s()))),
        BoolR => reg(regs::br_name(g(insn.r()))),
        S => Token::int(g(insn.s()) as i64, 1),
        T => Token::int(g(insn.t()) as i64, 1),
        Imm4 => Token::int(g(insn.imm4()) as i64, 1),
        Imm8 => Token::int(g(insn.imm8()) as i64, 1),
        Simm8 => Token::int(gi(insn.simm8()), 1),
        Simm8S8 => Token::int(gi(insn.simm8()) << 8, 4),
        RotwSimm4 => Token::int(gi(insn.rotw_simm4()), 1),
        Target => Token::addr(gi(insn.target_offset(addr))),
        Mem => Token::addr(gi(insn.mem_offset(addr))),
        B4const => Token::int(gi(insn.b4const()), 4),
        B4constu => Token::int(gi(insn.b4constu()), 4),
        Inl0x8 => Token::int(gi(insn.inline0()), 1),
        Inl0x32 => Token::int(gi(insn.inline0()), 4),
        ExtuiShift => Token::int(gi(insn.extui_shiftimm()), 1),
        Inl1x8 => Token::int(gi(insn.inline1()), 1),
        ClampsImm => Token::int(g(insn.t()) as i64 + 7, 1),
        S32eImm => Token::int(((g(insn.r()) as i64) << 2) - 64, 1),
        MacMr => reg(regs::mr_name(g(insn.r()))),
        MacDest => reg(insn.mac_destination().map_or("", |r| r.name())),
        MacBase => reg(insn.mac_base().map_or("", |r| r.name())),
        MacLeft => reg(insn.mac_left().map_or("", |r| r.name())),
        MacRight => reg(insn.mac_right().map_or("", |r| r.name())),
    }
}

/// Append the reference disassembly tokens of `insn` at `addr` to `out`.
///
/// Allocation happens only if `out` has to grow (at most 9 tokens).
pub fn disassemble(insn: &Insn, addr: u32, out: &mut Vec<Token>) {
    // Mnemonic token: RSR/WSR/XSR/RUR/WUR render as "RSR.<name>".
    let mut mnem = TokenText::from_str_lossy(insn.mnemonic());
    let user = insn.user_reg();
    let special = insn.special_reg();
    if let Some(sr) = special {
        mnem.push(b'.');
        match regs::special_reg(sr) {
            Some((name, _)) => mnem.push_str(name),
            None => mnem.push_dec(sr as i64),
        }
    } else if let Some(ur) = user {
        mnem.push(b'.');
        match regs::user_reg(ur) {
            Some((name, _)) => mnem.push_str(name),
            None => mnem.push_dec(ur as i64),
        }
    }
    let mlen = mnem.len();
    out.push(Token {
        kind: TokenKind::Instruction,
        text: mnem,
        value: 0,
        size: 0,
    });
    const SPACES: &str = "        ";
    let spaces = if mlen >= 8 { 1 } else { 8 - mlen };
    out.push(Token::plain(TokenKind::Text, &SPACES[..spaces]));

    if special.is_some() || user.is_some() {
        out.push(operand_token(insn, At, addr));
        return;
    }
    let Some(list) = operands(insn) else {
        out.push(Token::plain(TokenKind::Text, "unimplemented_disass"));
        return;
    };
    for (i, &opd) in list.iter().enumerate() {
        if i > 0 {
            out.push(Token::plain(TokenKind::OperandSeparator, ", "));
        }
        out.push(operand_token(insn, opd, addr));
    }
}
