# binja-xtensa-rs

A native (Rust) Xtensa architecture plugin for Binary Ninja: decoder,
disassembler, LLIL lifter, calling convention and the windowed-register
analysis workflows, for ESP32/ESP32-S3-class (LX6/LX7) firmware.

It is a port of the Python `binja-xtensa` plugin. The port is held to
**byte-identical output**: for every one of the 2^24 three-byte encodings,
at two addresses, the instruction length, branch edges, disassembly tokens
and lifted LLIL must equal the Python plugin's. Known oddities of the
reference are reproduced on purpose and documented rather than fixed, so the
two plugins are interchangeable in existing databases and signature corpora.

## Why

Python architecture plugins pay for every core callback in the interpreter,
under the GIL. On a 1.4 MB ESP32 application (about 10,000 functions) a
Binary Ninja analysis with the Python plugin took 3,877 s on a 24-core host.
A profile of that run attributed the time to the calling-convention callback
(49% of samples), the function workflows (39%) and per-instruction lifting
(14%); in 86% of samples at least one analysis thread was executing Python,
so adding worker threads does not help. For comparison, Binary Ninja's
native RISC-V architecture analysed an ESP32-C6 application of similar size
(10,479 functions) in 42 s on the same host.

## Status

| Component | State | Verification |
|---|---|---|
| `xtensa-isa`: decoder + disassembler (no dependencies) | done | all 2^24 encodings and all 1-/2-byte inputs byte-identical to the reference; ~300 M decodes/s |
| Architecture model: registers, register stack, intrinsics, calling convention | done | model dump identical to the reference |
| Instruction info and text callbacks | done | identical on every encoding checked so far |
| LLIL lifter | in progress | exhaustive per-encoding differential test |
| Function workflows (hardware loops, window tails, vector binding) | done; 8 of 10,474 functions on one ESP32 image under investigation | whole-binary differential test (`fn_dump.py`/`fn_compare.py`) |
| ESP firmware image loader | planned | |

## Layout

- `crates/xtensa-isa`: dependency-free decoder and disassembler, `#![forbid(unsafe_code)]`.
- `crates/binja-xtensa`: the Binary Ninja plugin (`cdylib`). Registers the
  architecture through the core C API (`ffi_arch.rs`) and lifts through a thin
  builder (`il.rs`) that issues the same core calls as Binary Ninja's Python
  LLIL API, which is what makes byte-identical IL achievable.
- `oracle/`, `harness/`: the differential testing tools. `gen_golden.py`
  runs the reference decoder over every encoding without Binary Ninja;
  `il_dump.py` dumps info/text/LLIL for every encoding through a running core
  for either plugin; `compare.py` diffs two dumps.
- `golden/`: digests and the reference architecture model (not the 2.8 GB
  dumps themselves).

## Building

The plugin links against the Binary Ninja core of the version it targets
(currently 6.0.10905, API revision `775c3b5e`). A Docker build environment
with the matching toolchain is provided:

```bash
docker build -t binja-xtensa-rs-build:1 -f docker/Dockerfile.build docker
BN_DIR=/path/to/binaryninja scripts/in-docker.sh cargo build --release -p binja-xtensa
```

Copy `libbinja_xtensa.so` into your Binary Ninja user `plugins/` directory.
The decoder crate builds anywhere with plain `cargo build -p xtensa-isa`.

## Verifying against the reference

```bash
# Decoder: regenerate the oracle from the Python plugin and compare digests.
python3 oracle/gen_golden.py --plugin-dir /path/to/binja_xtensa --out /tmp/golden
cargo run --profile golden -p xtensa-isa --example golden -- --out /tmp/golden-rs
cmp /tmp/golden/SHA256SUMS /tmp/golden-rs/SHA256SUMS

# Plugin: load both plugins (the native one under another name) and diff.
XTENSA_RS_ARCH_NAME=xtensa_rs bnpython3 harness/il_dump.py --arch xtensa_rs --out /tmp/rs
bnpython3 harness/il_dump.py --arch xtensa --out /tmp/ref
python3 harness/compare.py /tmp/ref /tmp/rs
```

The function workflows are compared on whole binaries. Load each plugin
alone (both registered as `xtensa`, in separate Binary Ninja user
directories), dump every function's blocks, lifted IL and LLIL, and diff:

```bash
BN_USER_DIRECTORY=/path/ref-user bnpython3 harness/fn_dump.py app.elf /tmp/ref.dump.gz --options @opts.json --trees
BN_USER_DIRECTORY=/path/rs-user  bnpython3 harness/fn_dump.py app.elf /tmp/rs.dump.gz  --options @opts.json --trees
python3 harness/fn_compare.py /tmp/ref.dump.gz /tmp/rs.dump.gz
```

See `PORTING.md` for the porting rules.

## License

MIT. The instruction semantics are derived from `binja-xtensa` (MIT,
Copyright 2025 Nicolae Binica, Zack Orndorff); see `LICENSE`.
