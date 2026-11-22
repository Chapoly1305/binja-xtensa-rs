//! Register tables: the reference `_special_reg_map` / `_user_reg_map`
//! (number, name, size in bytes) and register-name strings.

/// `_special_reg_map`: (number, name, size in bytes), ascending by number.
pub const SPECIAL_REGS: &[(u8, &str, u8)] = &[
    (0, "LBEG", 4),
    (1, "LEND", 4),
    (2, "LCOUNT", 4),
    (3, "SAR", 1),
    (4, "BR", 4),
    (5, "LITBASE", 4),
    (12, "SCOMPARE1", 4),
    (16, "ACCLO", 4),
    (17, "ACCHI", 1),
    (32, "M0", 4),
    (33, "M1", 4),
    (34, "M2", 4),
    (35, "M3", 4),
    (72, "WindowBase", 4),
    (73, "WindowStart", 4),
    (83, "PTEVADDR", 4),
    (89, "MMID", 4),
    (90, "RASID", 4),
    (91, "ITLBCFG", 4),
    (92, "DTLBCFG", 4),
    (96, "IBREAKENABLE", 1),
    (98, "CACHEATTR", 4),
    (99, "ATOMCTL", 1),
    (104, "DDR", 4),
    (106, "MEPC", 4),
    (107, "MEPS", 4),
    (108, "MESAVE", 4),
    (109, "MESR", 4),
    (110, "MECR", 3),
    (111, "MEVADDR", 4),
    (128, "IBREAKA0", 4),
    (129, "IBREAKA1", 4),
    (144, "DBREAKA0", 4),
    (145, "DBREAKA1", 4),
    (160, "DBREAKC0", 4),
    (161, "DBREAKC1", 4),
    (177, "EPC1", 4),
    (178, "EPC2", 4),
    (179, "EPC3", 4),
    (180, "EPC4", 4),
    (181, "EPC5", 4),
    (182, "EPC6", 4),
    (183, "EPC7", 4),
    (192, "DEPC", 4),
    (194, "EPS2", 4),
    (195, "EPS3", 4),
    (196, "EPS4", 4),
    (197, "EPS5", 4),
    (198, "EPS6", 4),
    (199, "EPS7", 4),
    (209, "EXCSAVE1", 4),
    (210, "EXCSAVE2", 4),
    (211, "EXCSAVE3", 4),
    (212, "EXCSAVE4", 4),
    (213, "EXCSAVE5", 4),
    (214, "EXCSAVE6", 4),
    (215, "EXCSAVE7", 4),
    (224, "CPENABLE", 1),
    (226, "INTERRUPT", 4),
    (227, "INTCLEAR", 4),
    (228, "INTENABLE", 4),
    (230, "PS", 4),
    (231, "VECBASE", 4),
    (232, "EXCCAUSE", 1),
    (233, "DEBUGCAUSE", 2),
    (234, "CCOUNT", 4),
    (235, "PRID", 4),
    (236, "ICOUNT", 4),
    (237, "ICOUNTLEVEL", 1),
    (238, "EXCVADDR", 4),
    (240, "CCOMPARE0", 4),
    (241, "CCOMPARE1", 4),
    (242, "CCOMPARE2", 4),
    (244, "MISC0", 4),
    (245, "MISC1", 4),
    (246, "MISC2", 4),
    (247, "MISC3", 4),
];

/// `_user_reg_map`: (number, name, size in bytes).
pub const USER_REGS: &[(u8, &str, u8)] = &[(231, "THREADPTR", 4), (232, "FCR", 4), (233, "FSR", 4)];

const fn build_index(table: &[(u8, &str, u8)]) -> [u8; 256] {
    let mut idx = [u8::MAX; 256];
    let mut i = 0;
    while i < table.len() {
        idx[table[i].0 as usize] = i as u8;
        i += 1;
    }
    idx
}

static SPECIAL_INDEX: [u8; 256] = build_index(SPECIAL_REGS);
static USER_INDEX: [u8; 256] = build_index(USER_REGS);

/// Look up a special register: `(name, size)`.
#[inline]
pub fn special_reg(sr: u8) -> Option<(&'static str, u8)> {
    let i = SPECIAL_INDEX[sr as usize];
    SPECIAL_REGS.get(i as usize).map(|&(_, n, s)| (n, s))
}

/// Look up a user register: `(name, size)`.
#[inline]
pub fn user_reg(ur: u8) -> Option<(&'static str, u8)> {
    let i = USER_INDEX[ur as usize];
    USER_REGS.get(i as usize).map(|&(_, n, s)| (n, s))
}

macro_rules! names {
    ($p:literal) => {
        [
            concat!($p, "0"),
            concat!($p, "1"),
            concat!($p, "2"),
            concat!($p, "3"),
            concat!($p, "4"),
            concat!($p, "5"),
            concat!($p, "6"),
            concat!($p, "7"),
            concat!($p, "8"),
            concat!($p, "9"),
            concat!($p, "10"),
            concat!($p, "11"),
            concat!($p, "12"),
            concat!($p, "13"),
            concat!($p, "14"),
            concat!($p, "15"),
        ]
    };
}

static AR: [&str; 16] = names!("a");
static FR: [&str; 16] = names!("f");
static BR: [&str; 16] = names!("b");
static MR: [&str; 16] = names!("m");

/// `a0`..`a15` (index masked to 4 bits).
#[inline]
pub fn ar_name(n: u8) -> &'static str {
    AR[(n & 15) as usize]
}
/// `f0`..`f15`.
#[inline]
pub fn fr_name(n: u8) -> &'static str {
    FR[(n & 15) as usize]
}
/// `b0`..`b15`.
#[inline]
pub fn br_name(n: u8) -> &'static str {
    BR[(n & 15) as usize]
}
/// `m0`..`m15` (the reference renders LDINC/LDDEC's `m<r>` for any r).
#[inline]
pub fn mr_name(n: u8) -> &'static str {
    MR[(n & 15) as usize]
}
