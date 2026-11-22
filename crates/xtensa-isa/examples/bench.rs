//! Decode all 2^24 three-byte encodings and report throughput.
//!
//! `cargo run --release -p xtensa-isa --example bench [-- ROUNDS]`

use std::hint::black_box;
use std::time::Instant;

use xtensa_isa::{decode, decode_word, disassemble};

fn main() {
    let rounds: u32 = std::env::args()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    const N: u32 = 1 << 24;

    // Slice API: decode(&[u8]) over a buffer holding every encoding.
    let mut buf = Vec::with_capacity(N as usize * 3);
    for w in 0..N {
        buf.extend_from_slice(&w.to_le_bytes()[..3]);
    }
    let mut best_slice = f64::MAX;
    let mut best_word = f64::MAX;
    let mut checksum = 0u64;
    for _ in 0..rounds {
        let t = Instant::now();
        for chunk in black_box(&buf).chunks_exact(3) {
            if let Ok(i) = decode(chunk) {
                checksum = checksum.wrapping_add(i.opcode as u64 + i.len as u64);
            }
        }
        best_slice = best_slice.min(t.elapsed().as_secs_f64());

        let t = Instant::now();
        for w in 0..N {
            let i = decode_word(black_box(w));
            checksum = checksum.wrapping_add(i.opcode as u64 + i.valid as u64);
        }
        best_word = best_word.min(t.elapsed().as_secs_f64());
    }

    // Decode + disassemble (one address), reusing the token buffer.
    let mut toks = Vec::with_capacity(16);
    let t = Instant::now();
    for w in 0..N {
        let i = decode_word(black_box(w));
        toks.clear();
        disassemble(&i, 0x4008_0000, &mut toks);
        checksum = checksum.wrapping_add(toks.len() as u64);
    }
    let dis = t.elapsed().as_secs_f64();

    let m = |s: f64| N as f64 / s / 1e6;
    println!(
        "decode(&[u8]):        {:7.1} M decodes/s (best of {rounds}, {:.3}s per 2^24)",
        m(best_slice),
        best_slice
    );
    println!(
        "decode_word(u32):     {:7.1} M decodes/s (best of {rounds}, {:.3}s per 2^24)",
        m(best_word),
        best_word
    );
    println!(
        "decode+disassemble:   {:7.1} M insns/s   ({dis:.3}s per 2^24)",
        m(dis)
    );
    println!("checksum {checksum}");
}
