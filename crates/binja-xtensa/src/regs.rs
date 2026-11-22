//! Register and intrinsic lookup by name, mirroring the reference's
//! `arch.get_reg_index(name)`, which raises for a name the architecture does
//! not define (for example `a16` from an out-of-range operand). That raise is
//! observable: the lift callback fails and keeps the IL appended so far. So
//! every lookup here returns `Result`, and lifter code propagates it with `?`.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::il::{I, R};
use crate::lift::Raise;
use crate::model;

fn reg_map() -> &'static HashMap<&'static str, u32> {
    static MAP: OnceLock<HashMap<&'static str, u32>> = OnceLock::new();
    MAP.get_or_init(|| {
        model::REGISTERS.iter().enumerate().map(|(i, (n, _))| (*n, i as u32)).collect()
    })
}

/// `arch.get_reg_index(name)`.
pub fn reg(name: &str) -> Result<R, Raise> {
    reg_map().get(name).map(|&i| R(i)).ok_or(Raise::NoSuchRegister)
}

/// `prefix + str(n)`, e.g. `numbered("a", 3)` is `a3`. Cached for the common
/// register files so the hot path does not format strings.
pub fn numbered(prefix: &str, n: i64) -> Result<R, Raise> {
    struct Files {
        a: [Option<u32>; 64],
        ar: [Option<u32>; 64],
        f: [Option<u32>; 64],
        b: [Option<u32>; 64],
    }
    static FILES: OnceLock<Files> = OnceLock::new();
    let files = FILES.get_or_init(|| {
        let build = |p: &str| std::array::from_fn(|i| reg_map().get(format!("{p}{i}").as_str()).copied());
        Files { a: build("a"), ar: build("ar"), f: build("f"), b: build("b") }
    });
    let table = match prefix {
        "a" => Some(&files.a),
        "ar" => Some(&files.ar),
        "f" => Some(&files.f),
        "b" => Some(&files.b),
        _ => None,
    };
    match table {
        Some(t) if (0..64).contains(&n) => t[n as usize].map(R).ok_or(Raise::NoSuchRegister),
        Some(_) => Err(Raise::NoSuchRegister),
        None => reg(&format!("{prefix}{n}")),
    }
}

/// `arch.get_intrinsic_index(name)`.
pub fn intrinsic(name: &str) -> Result<I, Raise> {
    static MAP: OnceLock<HashMap<&'static str, u32>> = OnceLock::new();
    let map = MAP.get_or_init(|| {
        model::INTRINSICS.iter().enumerate().map(|(i, d)| (d.name, i as u32)).collect()
    });
    map.get(name).map(|&i| I(i)).ok_or(Raise::NoSuchIntrinsic)
}
