//! Unit tests: representative encodings of every format (full oracle lines
//! copied from the golden data), plus API-level checks.

use crate::oracle::LineWriter;
use crate::*;

fn key_bytes(key: &str) -> Vec<u8> {
    let raw: Vec<u8> = (0..key.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&key[i..i + 2], 16).unwrap())
        .collect();
    if raw.len() == 3 {
        // shard keys are the word in hex, i.e. big-endian
        vec![raw[2], raw[1], raw[0]]
    } else {
        raw
    }
}

#[test]
fn golden_samples_match() {
    let data = include_str!("testdata/golden_samples.tsv");
    let mut w = LineWriter::new();
    let mut formats = std::collections::HashSet::new();
    for line in data.lines() {
        let key = line.split('\t').next().unwrap();
        let mut out = Vec::new();
        w.write_line(&key_bytes(key), &mut out);
        assert_eq!(String::from_utf8(out).unwrap(), line, "encoding {key}");
        if let Ok(i) = decode(&key_bytes(key)) {
            formats.insert(i.format);
        }
    }
    // every Format plus the reserved-slot `None`
    assert_eq!(formats.len(), 13);
}

#[test]
fn short_inputs() {
    assert_eq!(decode(&[]), Err(DecodeError::ShortInput));
    // narrow instruction, 1 byte: reads byte 1 -> IndexError
    assert_eq!(decode(&[0x1d]), Err(DecodeError::ShortInput));
    // reserved op0 = 14: only byte 0 read -> ILL of length 3, even from 1 byte
    let i = decode(&[0x0e]).unwrap();
    assert_eq!(
        (i.opcode, i.len, i.valid, i.format),
        (Opcode::Ill, 3, false, None)
    );
    assert_eq!(i.op0(), Some(14));
    assert_eq!(i.r(), None);
    // 2-byte narrow decode
    let i = decode(&[0x0d, 0x00]).unwrap();
    assert_eq!((i.opcode, i.len), (Opcode::MovN, 2));
    // 3-byte format from 2 bytes
    assert_eq!(decode(&[0x36, 0x41]), Err(DecodeError::ShortInput));
    // longer input: only three bytes read
    assert_eq!(
        decode(&[0x36, 0x41, 0x00, 0xff]).unwrap(),
        decode(&[0x36, 0x41, 0x00]).unwrap()
    );
}

#[test]
fn fields_and_helpers() {
    // beqi a3, 4, <target>: op0=6 n=2 m=0 s=3 r=4 imm8=0xfe
    let i = decode(&[0x26, 0x43, 0xfe]).unwrap();
    assert_eq!(i.opcode, Opcode::Beqi);
    assert_eq!(i.format, Some(Format::Bri8));
    assert_eq!(i.b4const(), Some(4));
    assert_eq!(i.simm8(), Some(-2));
    assert_eq!(i.target_offset(0x1000), Some(0x1002));
    assert_eq!(i.mem_offset(0x1000), None);
    assert_eq!(i.t(), None);
    let f = i.fields();
    assert_eq!(
        (f.r, f.s, f.m, f.n, f.imm8),
        (Some(4), Some(3), Some(0), Some(2), Some(0xfe))
    );

    // l32r a2, <lit>
    let i = decode(&[0x21, 0xff, 0xff]).unwrap();
    assert_eq!(i.opcode, Opcode::L32r);
    assert_eq!(i.mem_offset(0x4008_0000), Some(0x4007_fffc));

    // extui
    let i = decode(&[0x00, 0x00, 0xa5]).unwrap();
    assert_eq!(i.extui_shiftimm(), Some(16));
    assert_eq!(i.inline1(), Some(11));
    assert_eq!(i.inline0(), None);
    assert_eq!(i.inline(1, 0), Some(11));
}

#[test]
fn mac16_attributes() {
    // MULA.DD.HL.LDINC m1, a5, m0, m3 (raw 0x091544)
    let i = decode(&[0x44, 0x15, 0x09]).unwrap();
    assert_eq!(i.opcode, Opcode::MulaDdHlLdinc);
    assert_eq!(i.mac_kind(), Some(MacKind::Dd));
    assert_eq!(i.mac_operation(), Some(MacOperation::Mula));
    assert_eq!(i.mac_half(), Some(1));
    assert_eq!(i.mac_load_delta(), Some(4));
    assert_eq!(i.mac_destination(), Some(MacReg::M(1)));
    assert_eq!(i.mac_base(), Some(MacReg::A(5)));
    assert_eq!(i.mac_left(), Some(MacReg::M(0)));
    assert_eq!(i.mac_right(), Some(MacReg::M(3)));

    // MULS.AD.HH a2, m3 (raw 0x3f0244)
    let i = decode(&[0x44, 0x02, 0x3f]).unwrap();
    assert_eq!(i.mac_kind(), Some(MacKind::Ad));
    assert_eq!(i.mac_operation(), Some(MacOperation::Muls));
    assert_eq!(i.mac_half(), Some(3));
    assert_eq!(i.mac_load_delta(), None);
    assert_eq!(i.mac_base(), None);
    assert_eq!(i.mac_left().map(MacReg::name), Some("a2"));
    assert_eq!(i.mac_right().map(MacReg::name), Some("m3"));

    // LDINC is not a "mac_kind" instruction in the reference
    let i = decode(&[0x04, 0x23, 0x80]).unwrap();
    assert_eq!(i.opcode, Opcode::Ldinc);
    assert_eq!(i.mac_kind(), None);

    // every MAC opcode reports a kind consistent with its mnemonic
    for &op in Opcode::ALL {
        let m = op.mnemonic();
        let is_mac = m.matches('.').count() >= 2 && m.starts_with(['U', 'M']);
        let i = Insn::from_parts(op, 3, true, Some(Format::Rrr), 0, [0; 3]);
        assert_eq!(i.mac_kind().is_some(), is_mac, "{m}");
        if let Some(k) = i.mac_kind() {
            assert_eq!(&m[m.find('.').unwrap() + 1..][..2], k.as_str());
            assert!(m.starts_with(i.mac_operation().unwrap().as_str()));
            assert_eq!(i.mac_load_delta().is_some(), m.contains(".LD"));
        }
    }
}

#[test]
fn opcode_table() {
    assert_eq!(OPCODE_COUNT, 317);
    let mut seen = std::collections::HashSet::new();
    for &op in Opcode::ALL {
        assert!(seen.insert(op.mnemonic()));
    }
    assert_eq!(Opcode::AddN.mnemonic(), "ADD.N");
    assert_eq!(Opcode::MulaDdLlLdinc.mnemonic(), "MULA.DD.LL.LDINC");
}

#[test]
fn registers() {
    assert_eq!(regs::special_reg(3), Some(("SAR", 1)));
    assert_eq!(regs::special_reg(110), Some(("MECR", 3)));
    assert_eq!(regs::special_reg(6), None);
    assert_eq!(regs::user_reg(231), Some(("THREADPTR", 4)));
    assert_eq!(SPECIAL_REGS.len(), 77);
    let i = decode(&[0x30, 0xe7, 0xe3]).unwrap();
    assert_eq!(i.user_reg_name(), Some("THREADPTR"));
    assert_eq!(i.special_reg(), None);
}

#[test]
fn insn_is_small() {
    assert!(std::mem::size_of::<Insn>() <= 12);
}

#[test]
fn never_panics_on_any_short_prefix() {
    let mut toks = Vec::new();
    for w in 0..=0xffffu32 {
        let b = [w as u8, (w >> 8) as u8];
        for n in 0..=2 {
            if let Ok(i) = decode(&b[..n]) {
                toks.clear();
                disassemble(&i, 0, &mut toks);
                disassemble(&i, u32::MAX, &mut toks);
            }
        }
    }
}
