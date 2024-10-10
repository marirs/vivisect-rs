use std::collections::HashMap;
use lazy_static::lazy_static;

// region: -- Architecture Constants

pub const ARCH_DEFAULT: i32 = 0 << 16;
pub const ARCH_I386: i32 = 1 << 16;
pub const ARCH_AMD64: i32 = 2 << 16;
pub const ARCH_ARMV7: i32 = 3 << 16;
pub const ARCH_THUMB16: i32 = 4 << 16;
pub const ARCH_THUMB: i32 = 5 << 16;
pub const ARCH_MSP430: i32 = 6 << 16;
pub const ARCH_H8: i32 = 7 << 16;
pub const ARCH_MASK: i64 = 0xffff0000; // Masked into IF_FOO and BR_FOO values.
// endregion

// region: -- Instruction Flags
pub const IF_NOFALL: i32 = 0x01;
pub const IF_PRIV: i32 = 0x02;
pub const IF_CALL: i32 = 0x04;
pub const IF_BRANCH: i32 = 0x08;
pub const IF_RET: i32 = 0x10;
pub const IF_COND: i32 = 0x20;

/// Set if this instruction repeats (including 0 times)
pub const IF_REPEAT: i32 = 0x40;

pub const IF_BRANCH_COND: i32 = IF_COND | IF_BRANCH;
// endregion

// region: -- Branch Flags
/// The branch is a procedure call
pub const BR_PROC: i32 = 1<<0;
/// The branch is conditional
pub const BR_COND: i32 = 1<<1;
/// The branch is dereferenced into PC(call [0x41414141])
pub const BR_DEREF: i32 = 1<<2;
/// The branch is the base of a pointer array of jmp/call slots
pub const BR_TABLE: i32 = 1<<3;
/// The branch is a fall-through.
pub const BR_FALL: i32 = 1<<4;
/// The branch is switches opcode formats.
pub const BR_ARCH: i32 = 1<<5;
// endregion

// region: -- Calling Convention Constants
/// Argument is stored in a register.
pub const CC_REG: i32 = 1<<0;
/// Argument is stored on the stack.
pub const CC_STACK: i32 = 1<<1;
/// All following arguments are stored on the stack.
pub const CC_STACK_INF: i32 = 1<<2;
/// Callee cleans up the stack.
pub const CC_CALLEE_CLEANUP: i32 = 1<<3;
/// Caller cleans up the stack.
pub const CC_CALLER_CLEANUP: i32 = 1<<4;
// endregion

// region: -- Meta-Register Constants
pub const RMETA_MASK: i64 = 0xffff0000;
pub const RMETA_NMASK: i64 = 0x0000ffff;
// endregion

// region: -- Endianness Constants
/// Little-endian
pub const ENDIAN_LSB: i32 = 0;
/// Big-endian
pub const ENDIAN_MSB: i32 = 1;

#[derive(Clone, Debug)]
/// The default endianness for the architecture.
pub enum Endianess {
    /// Little-endian
    Little,
    /// Big-endian
    Big,
}

impl Endianess {
    pub fn from_i32(val: i32) -> Self {
        match val {
            ENDIAN_LSB => Endianess::Little,
            ENDIAN_MSB => Endianess::Big,
            _ => panic!("Invalid endianess value: {}", val),
        }
    }
    
    pub fn to_i32(&self) -> i32 {
        match self {
            Endianess::Little => ENDIAN_LSB,
            Endianess::Big => ENDIAN_MSB,
        }
    }
}
// endregion

// region: -- Memory Map Permission Flags
pub const MM_NONE: i32 = 0x00;
pub const MM_READ: i32 = 0x04;
pub const MM_WRITE: i32 = 0x02;
pub const MM_EXEC: i32 = 0x01;
pub const MM_SHARED: i32 = 0x08;

pub const MM_READ_WRITE: i32 = MM_READ | MM_WRITE;
pub const MM_READ_EXEC: i32 = MM_READ | MM_EXEC;
pub const MM_READ_WRITE_EXEC: i32 = MM_READ | MM_WRITE | MM_EXEC;

// endregion

// region: -- Page Constants
pub const PAGE_SIZE: i32 = 1<<12;
pub const PAGE_NMASK: i32 = PAGE_SIZE - 1;
pub const PAGE_MASK: i32 = !PAGE_NMASK;
// endregion

lazy_static! {
    pub static ref ARCH_NAMES: HashMap<i32, &'static str> = HashMap::from([
        (ARCH_DEFAULT, "default"),
        (ARCH_I386, "i386"),
        (ARCH_AMD64, "amd64"),
        (ARCH_ARMV7, "armv7"),
        (ARCH_THUMB16, "thumb16"),
        (ARCH_THUMB, "thumb"),
        (ARCH_MSP430, "msp430"),
        (ARCH_H8, "h8"),
    ]);

    pub static ref ARCH_NAMES_REV: HashMap<&'static str, i32> = HashMap::from([
        ("default", ARCH_DEFAULT),
        ("i386", ARCH_I386),
        ("amd64", ARCH_AMD64),
        ("armv7", ARCH_ARMV7),
        ("thumb16", ARCH_THUMB16),
        ("thumb", ARCH_THUMB),
        ("msp430", ARCH_MSP430),
        ("h8", ARCH_H8),
    ]);

    pub static ref PERMISSION_NAMES: Vec<String> = {
        let mut perm_names = vec![
            "No Access".to_string(),
            "Execute".to_string(),
            "Write".to_string(),
            "Write/Exec".to_string(),
            "Read".to_string(),
            "Read/Exec".to_string(),
            "Read/Write".to_string(),
            "Read/Write/Exec".to_string(),
        ];
        for perm_name in perm_names.clone() {
            let shared_perm = format!("Shared: {perm_name}");
            perm_names.push(shared_perm);
        }
        perm_names
    };
}