//! Exhaustive comparison against the golden oracle.
//!
//! Set `XTENSA_GOLDEN_DIR` to the directory holding `shard_00.tsv` ..
//! `shard_ff.tsv` and `short.tsv` (e.g. the `xtensa_golden_v1` data set);
//! without it the test is skipped. Every line is compared; the first few
//! mismatches of each file are reported. Run it with `--release` for speed.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use xtensa_isa::oracle::LineWriter;

const MAX_REPORT: usize = 3;

fn compare(path: &Path, ours: &[u8]) -> Result<(), String> {
    let golden = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if golden == ours {
        return Ok(());
    }
    let name = path.file_name().unwrap().to_string_lossy().into_owned();
    let mut report = Vec::new();
    let (mut g, mut o) = (golden.split(|&b| b == b'\n'), ours.split(|&b| b == b'\n'));
    let mut lineno = 0usize;
    let mut total = 0usize;
    loop {
        lineno += 1;
        match (g.next(), o.next()) {
            (None, None) => break,
            (gl, ol) if gl == ol => continue,
            (gl, ol) => {
                total += 1;
                if report.len() < MAX_REPORT {
                    let s = |l: Option<&[u8]>| {
                        l.map_or("<eof>".into(), |l| String::from_utf8_lossy(l).into_owned())
                    };
                    report.push(format!(
                        "  {name}:{lineno}\n    golden: {}\n    ours:   {}",
                        s(gl),
                        s(ol)
                    ));
                }
            }
        }
    }
    Err(format!(
        "{name}: {total} mismatching lines\n{}",
        report.join("\n")
    ))
}

#[test]
fn golden_exhaustive() {
    let Some(dir) = std::env::var_os("XTENSA_GOLDEN_DIR").map(PathBuf::from) else {
        eprintln!("XTENSA_GOLDEN_DIR not set; skipping exhaustive golden comparison");
        return;
    };
    let next = AtomicUsize::new(0);
    let failures = Mutex::new(Vec::new());
    let jobs = std::thread::available_parallelism().map_or(1, |n| n.get());
    std::thread::scope(|scope| {
        for _ in 0..jobs {
            scope.spawn(|| {
                let mut w = LineWriter::new();
                let mut buf = Vec::with_capacity(16 << 20);
                loop {
                    let item = next.fetch_add(1, Ordering::Relaxed);
                    if item > 256 {
                        break;
                    }
                    buf.clear();
                    let file = if item == 256 {
                        w.short(&mut buf);
                        "short.tsv".to_string()
                    } else {
                        w.shard(item as u8, &mut buf);
                        format!("shard_{item:02x}.tsv")
                    };
                    if let Err(e) = compare(&dir.join(file), &buf) {
                        failures.lock().unwrap().push((item, e));
                    }
                }
            });
        }
    });
    let mut failures = failures.into_inner().unwrap();
    failures.sort();
    if !failures.is_empty() {
        let msgs: Vec<_> = failures.into_iter().map(|(_, e)| e).collect();
        panic!("{} files differ:\n{}", msgs.len(), msgs.join("\n"));
    }
}
