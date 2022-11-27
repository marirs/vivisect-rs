#![allow(dead_code, unused)]

pub const VWE_ADDLOCATION : i32 = 1; // (va,size,ltype,tinfo)
pub const VWE_DELLOCATION:i32 = 2; // (va,size,ltype,tinfo)

pub const VWE_ADDSEGMENT: i32 = 3; // (va, size, name, filename)
pub const VWE_DELSEGMENT: i32 = 4; // FIXME IMPLEMENT

pub const VWE_ADDRELOC: i32        = 5; // (va,rtype)
pub const VWE_DELRELOC: i32       = 6; // // FIXME IMPLEMENT

pub const VWE_ADDMODULE: i32       = 7; // DEPRECATED
pub const VWE_DELMODULE : i32      = 8; // DEPRECATED

pub const VWE_ADDFMODULE : i32     = 9;  // DEPRECATED
pub const VWE_DELFMODULE: i32      = 10; // DEPRECATED

pub const VWE_ADDFUNCTION: i32     = 11; // (va, meta)
pub const VWE_DELFUNCTION: i32     = 12; // va

pub const VWE_SETFUNCARGS: i32     = 13; // (fva, arglist)
pub const VWE_SETFUNCMETA: i32     = 14; // (funcva, key, value)

pub const VWE_ADDCODEBLOCK: i32    = 15; // (va, size, funcva)
pub const VWE_DELCODEBLOCK: i32    = 16; // FIXME IMPLEMENT

pub const VWE_ADDXREF: i32         = 17; // (fromva, tova, reftype)
pub const VWE_DELXREF: i32         = 18; // (fromva, tova, reftype)

pub const VWE_SETNAME : i32        = 19; // (va, name)

pub const VWE_ADDMMAP: i32         = 20; // (va, perms, bytes) //OMG MAYBE BIG
pub const VWE_DELMMAP: i32         = 21; // FIXME IMPLEMENT

pub const VWE_ADDEXPORT: i32       = 22; // export object (not for long)
pub const VWE_DELEXPORT: i32       = 23; // export object (not for long)

pub const VWE_SETMETA : i32        = 24; // (key, val)

pub const VWE_COMMENT : i32        = 25; // (va, comment)

pub const VWE_ADDFILE: i32         = 26; // (normname, baseaddr, md5sum)
pub const VWE_DELFILE: i32         = 27;  // FIXME IMPLEMENT

pub const VWE_SETFILEMETA: i32     = 28; // (fname, key, value)

pub const VWE_ADDCOLOR : i32       = 29; // (mapname, colordict)
pub const VWE_DELCOLOR : i32       = 30; // mapname

pub const VWE_ADDVASET : i32       = 31; // (name, setdict)
pub const VWE_DELVASET : i32       = 32; // setname

pub const VWE_ADDFREF: i32         = 33; // (va, operidx, value)
pub const VWE_DELFREF: i32         = 34; // FIXME IMPLEMENT

pub const VWE_SETVASETROW: i32     = 35; // (name, rowtup)
pub const VWE_DELVASETROW: i32     = 36; // (name, va)

pub const VWE_ADDFSIG : i32        = 37; // (sigbytes, sigmask)
pub const VWE_DELFSIG: i32         = 38; // FIXME IMPLEMENT

pub const VWE_FOLLOWME: i32        = 39; // LEGACY - not in use.
pub const VWE_CHAT: i32            = 40; // (username, message)

pub const VWE_SYMHINT: i32         = 41; // (va, idx, hint)
pub const VWE_AUTOANALFIN: i32     = 42; // (starttime, endtime)

pub const VWE_MAX: i32             = 43;

// Constants for vivisect_rs "transient" events which flow through
// the event subsystem but are not recorded to the workspace.
pub const VTE_MASK: u32 = 0x80000000;
pub const VTE_IAMLEADER: i32 = 1; // (uuid,user,followname)
pub const VTE_FOLLOWME: i32 = 2; // (uuid,expr)
pub const VTE_KILLLEADER: i32 = 3; // (uuid)
pub const VTE_MODLEADER: i32 = 4; // (uuid,user,followname)
pub const VTE_MAX: i32 = 5;

// API fields
pub const API_RET_TYPE: i32 = 0;
pub const API_RET_NAME: i32 = 1;
pub const API_CCONV: i32 = 2;
pub const API_FUNC_NAME: i32 = 3;
pub const API_ARG_START: i32 = 4;

// Reference Types
// NOTE: All XREFs may have type specific flags
pub const REF_CODE: i32 = 1; // A branch/call
pub const REF_DATA: i32 = 2; // A memory dereference
pub const REF_PTR : i32 = 3; // A pointer immediate (may be in operand *or* part of LOC_PTR)

pub enum RefTypeNames {
    RefCode,
    RefData,
    RefPtr
}

//NOTE: The flag values for RefCode are the envi.BR_FOO flags
//      which describe opcode branches.

//NOTE: All locations ltypes may not change (backward compat)
pub const LOC_UNDEF : i32 = 0;  // An undefined "non-location"
pub const LOC_NUMBER : i32 = 1;  // A numerical value (non-pointer)
pub const LOC_STRING : i32 = 2;  // A null terminated string
pub const LOC_UNI : i32 = 3;  // A null terminated unicode string
pub const LOC_POINTER: i32 = 4;  // A type to hold a known-derefable pointer that is of appropriate length for arch
pub const LOC_OP : i32 = 5;  // An opcode
pub const LOC_STRUCT : i32 = 6;  // A custom structure (struct name is in tinfo)
pub const LOC_CLSID : i32 = 7;  // A clsid
pub const LOC_VFTABLE: i32 = 8;  // A c++ vftable
pub const LOC_IMPORT : i32 = 9;  // An import dword ptr
pub const LOC_PAD : i32 = 10;  // A sequence of bytes which is a pad (string nulls, MS hotpatch... (char is tinfo)
pub const LOC_MAX : i32 = 11;

pub const L_VA : i32   = 0;
pub const L_SIZE: i32  = 1;
pub const L_LTYPE: i32 = 2;
pub const L_TINFO: i32 = 3;

pub const CC_REG : i32 = 1 << 0;    // argument is stored in a register
pub const CC_STACK : i32 = 1 << 1;    // argument is stored on the stack
pub const CC_STACK_INF : i32 = 1 << 2;    // all following args are stored on the stack
pub const CC_CALLEE_CLEANUP : i32 = 1 << 3;    // callee cleans up the stack
pub const CC_CALLER_CLEANUP : i32 = 1 << 4;    // caller cleans up the stack

// meta-register constants
pub const RMETA_MASK : u32 = 0xffff0000;
pub const RMETA_NMASK: u32 = 0x0000ffff;

pub const ENDIAN_LSB : i32 = 0;
pub const ENDIAN_MSB : i32 = 1;

// Memory Map Permission Flags
pub const MM_NONE : i32 = 0x0;
pub const MM_READ : i32 = 0x4;
pub const MM_WRITE : i32 = 0x2;
pub const MM_EXEC : i32 = 0x1;
pub const MM_SHARED : i32 = 0x08;

pub const MM_READ_WRITE :  i32 = MM_READ | MM_WRITE;
pub const MM_READ_EXEC :  i32 = MM_READ | MM_EXEC;
pub const MM_RWX :  i32 = MM_READ | MM_WRITE | MM_EXEC;

// pub static mut PNAMES: Vec<&str> = vec![
// "No Access",
// "Execute",
// "Write",
// "Write/Exec",
// "Read",
// "Read/Exec",
// "Read/Write",
// "RWE"
// ];

pub const PAGE_SIZE : i32 = 1 << 12;
pub const PAGE_NMASK : i32 = PAGE_SIZE - 1;

pub const ARCH_DEFAULT : u32 = 0 << 16;   //arch 0 is; whatever the mem object has as default
pub const ARCH_I386 : i32 = 1 << 16;
pub const ARCH_AMD64 : i32 = 2 << 16;
pub const ARCH_ARMV7 : i32 = 3 << 16;
pub const ARCH_THUMB16 : i32 = 4 << 16;
pub const ARCH_THUMB : i32 = 5 << 16;
pub const ARCH_MSP430 : i32 = 6 << 16;
pub const ARCH_H8 : i32 = 7 << 16;
pub const ARCH_MASK : u32 = 0xffff0000;  // Masked; into IF_FOO and BR_FOO values

// pub const ARCH_NAMES: Vec<(i32, &str)> = vec![
//     (ARCH_DEFAULT, "default"),
//     (ARCH_I386, "i386"),
//     (ARCH_AMD64, "amd64"),
//     (ARCH_ARMV7, "arm"),
//     (ARCH_THUMB16, "thumb16"),
//     (ARCH_THUMB, "thumb"),
//     (ARCH_MSP430, "msp430"),
//     (ARCH_H8, "h8")
// ];
// 
// pub const ARCH_BY_NAME: Vec<(&str, i32)> = vec![
//     ("default", ARCH_DEFAULT),
//     ("i386", ARCH_I386),
//     ("amd64", ARCH_AMD64),
//     ("arm", ARCH_ARMV7),
//     ("armv6l", ARCH_ARMV7),
//     ("armv7l", ARCH_ARMV7),
//     ("thumb16", ARCH_THUMB16),
//     ("thumb", ARCH_THUMB),
//     ("thumb2", ARCH_THUMB),
//     ("msp430", ARCH_MSP430),
//     ("h8", ARCH_H8)
// ];

// Instruction flags (The first 8 bits are reserved for arch independant use std::collections::HashMap;
pub const IF_NOFALL : u32 = 0x01;  // Set if this instruction does *not* fall through
pub const IF_PRIV : u32 = 0x02;  // Set if this is a "privileged mode" instruction
pub const IF_CALL : u32 = 0x04;  // Set if this instruction branches to a procedure
pub const IF_BRANCH: u32 = 0x08;  // Set if this instruction branches
pub const IF_RET : u32 = 0x10;  // Set if this instruction terminates a procedure
pub const IF_COND : u32 = 0x20;  // Set if this instruction is conditional
pub const IF_REPEAT : u32 = 0x40;  // set if this instruction repeats (including 0 times)

pub const IF_BRANCH_COND : u32 = IF_COND | IF_BRANCH;

// Branch flags (flags returned by the getBranches() method on an opcode)
pub const BR_PROC : i32 = 1<<0;  // The branch target is a procedure (call <foo>)
pub const BR_COND : i32 = 1<<1;  // The branch target is conditional (jz <foo>)
pub const BR_DEREF : i32 = 1<<2;  // the branch target is *dereferenced* into PC (call [0x41414141])
pub const BR_TABLE : i32 = 1<<3;  // The branch target is the base of a pointer array of jmp/call slots
pub const BR_FALL : i32 = 1<<4;  // The branch is a "fall through" to the next instruction
pub const BR_ARCH : i32 = 1<<5;  // The branch *switches opcode formats*. ( ARCH_FOO in high bits )

pub const CB_VA: i32 = 0;
pub const CB_SIZE : i32 = 1;
pub const CB_FUNCVA : i32 = 2;

// Memory Map tuples are Area Compatable tuples that
// describe a loaded memory map
pub const MAP_VA : i32 = 0;
pub const MAP_SIZE : i32 = 1;
pub const MAP_PERMS : i32 = 2;
pub const MAP_FNAME : i32 = 3;

// Segment tuples are Area Compatable tuples that describe
// a "section" or "segment" inside a memory map.
pub const SEG_VA : i32 = 0;
pub const SEG_SIZE : i32 = 1;
pub const SEG_NAME : i32 = 2; // The name of the segment ".text" ".plt"
pub const SEG_FNAME: i32 = 3; // The *normalized* name of the file

// XREF tuples *not* area compatable tuples
pub const XR_FROM  : i32 = 0;
pub const XR_TO    : i32 = 1;
pub const XR_RTYPE : i32 = 2;
pub const XR_RFLAG : i32 = 3;

// Export Types
pub const EXP_UNTYPED  : u32 = 0xffffffff;
pub const EXP_FUNCTION : i32 = 0;
pub const EXP_DATA     : i32 = 1;

// Relocation types
pub const RTYPE_BASERELOC : i32 = 0; // VA contains a pointer to a va (and is assumed fixed up by parser)
pub const RTYPE_BASEOFF   : i32 = 1; // Add Base and Offset to a pointer at a memory location
pub const RTYPE_BASEPTR   : i32 = 2; // Like BASEOFF, but treated as a Pointer, not part of an instruction/assets.

pub const REBASE_TYPES: (i32, i32) = (RTYPE_BASEOFF, RTYPE_BASEPTR);

// Function Local Symbol Types
pub const LSYM_NAME : i32 = 0; // syminfo is a (typestr,name) tuple
pub const LSYM_FARG : i32 = 1; // syminfo is an argument index


// vaset "type" constants
pub const VASET_ADDRESS : i32 = 0;
pub const VASET_INTEGER : i32 = 1;
pub const VASET_STRING  : i32 = 2;
pub const VASET_HEXTUP  : i32 = 3;
pub const VASET_COMPLEX : i32 = 4;

// Symboliks effect types
pub const EFFTYPE_DEBUG : i32= 0;
pub const EFFTYPE_SETVAR : i32= 1;
pub const EFFTYPE_READMEM  : i32= 2;
pub const EFFTYPE_WRITEMEM : i32= 3;
pub const EFFTYPE_CALLFUNC : i32= 4;
pub const EFFTYPE_CONSTRAIN : i32= 5;

// symboliks object types
pub const SYMT_VAR    : i32 = 0;
pub const SYMT_ARG    : i32 = 1;
pub const SYMT_CALL   : i32 = 2;
pub const SYMT_MEM    : i32 = 3;
pub const SYMT_SEXT   : i32 = 4;
pub const SYMT_CONST  : i32 = 5;
pub const SYMT_LOOKUP : i32 = 6;
pub const SYMT_NOT    : i32 = 7;

pub const SYMT_OPER  : i32 = 0x00010000;
pub const SYMT_OPER_ADD : i32 = SYMT_OPER | 1;
pub const SYMT_OPER_SUB : i32 = SYMT_OPER | 2;
pub const SYMT_OPER_MUL : i32 = SYMT_OPER | 3;
pub const SYMT_OPER_DIV : i32 = SYMT_OPER | 4;
pub const SYMT_OPER_AND : i32 = SYMT_OPER | 5;
pub const SYMT_OPER_OR  : i32 = SYMT_OPER | 6;
pub const SYMT_OPER_XOR : i32 = SYMT_OPER | 7;
pub const SYMT_OPER_MOD : i32 = SYMT_OPER | 8;
pub const SYMT_OPER_LSHIFT : i32 = SYMT_OPER | 9;
pub const SYMT_OPER_RSHIFT : i32 = SYMT_OPER | 10;
pub const SYMT_OPER_POW : i32 = SYMT_OPER | 11;

pub const SYMT_CON : i32  = 0x00020000;
pub const SYMT_CON_EQ     : i32  = SYMT_CON | 1;
pub const SYMT_CON_NE     : i32  = SYMT_CON | 2;
pub const SYMT_CON_GT     : i32  = SYMT_CON | 3;
pub const SYMT_CON_GE     : i32  = SYMT_CON | 4;
pub const SYMT_CON_LT     : i32  = SYMT_CON | 5;
pub const SYMT_CON_LE     : i32  = SYMT_CON | 6;
pub const SYMT_CON_UNK    : i32  = SYMT_CON | 7;
pub const SYMT_CON_NOTUNK : i32  = SYMT_CON | 8;