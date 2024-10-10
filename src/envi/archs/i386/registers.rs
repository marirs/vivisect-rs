// """
// Home of the i386 module's register specs/code.
// """
// import envi.registers as e_reg
//
// ## Definitions for some of the i386 MSRs from intel...
// MSR_DEBUGCTL             = 0x01d9 # Intel p4 and forward, debug behavior control
// MSR_DEBUGCTL_LBR         = 0x0001 # last branch recording (in msr's)
// MSR_DEBUGCTL_BTF         = 0x0002 # single-step on branches (break on branch)
// MSR_DEBUGCTL_TR          = 0x0004 # enable sending "branch trace messages" !!
// MSR_DEBUGCTL_BTS         = 0x0008 # enable logging BTMs to circular buffer
// MSR_DEBUGCTL_BTINT       = 0x0010 # Branch-trace-interrupt (gen interrupt on BTS full)
// MSR_DEBUGCTL_BTS_OFF_OS  = 0x0020 # disable ring0 branch trace store
// MSR_DEBUGCTL_BTS_OFF_USR = 0x0040 # disable non-ring0 branch trace store
//
// MSR_SYSENTER_EIP         = 0x0176 # Where is EIP at sysenter?
//
// IA32_DS_AREA_MSR         = 0x0600 # pointer to the configured debug storage area
//
// i386regs = [
// ("eax",32),("ecx",32),("edx",32),("ebx",32),("esp",32),("ebp",32),("esi",32),("edi",32),
// # SIMD registers
// ("xmm0",128),("xmm1",128),("xmm2",128),("xmm3",128),("xmm4",128),("xmm5",128),("xmm6",128),("xmm7",128),
// # Debug registers
// ("debug0",32),("debug1",32),("debug2",32),("debug3",32),("debug4",32),("debug5",32),("debug6",32),("debug7",32),
// # Control registers
// ("ctrl0",32),("ctrl1",32),("ctrl2",32),("ctrl3",32),("ctrl4",32),("ctrl5",32),("ctrl6",32),("ctrl7",32),
// # Test registers
// ("test0", 32),("test1", 32),("test2", 32),("test3", 32),("test4", 32),("test5", 32),("test6", 32),("test7", 32),
// # Segment registers
// ("es", 16),("cs",16),("ss",16),("ds",16),("fs",16),("gs",16),
// # FPU Registers
// ("st0", 80),("st1", 80),("st2", 80),("st3", 80),("st4", 80),("st5", 80),("st6", 80),("st7", 80),
// # Leftovers ;)
// ("eflags", 32), ("eip", 32), ("fpsr", 16), ("fpcr", 16),
// # TODO there's a bunch of floating point stuff that we basically just ignore
// ]
//
// def getRegOffset(regs, regname):
// # NOTE: dynamically calculate this on import so we are less
// # likely to fuck it up...
// for i,(name,width) in enumerate(regs):
// if name == regname:
// return i
// raise Exception("getRegOffset doesn't know about: %s" % regname)
//
// # dynamically create REG_EAX and the like in our module
// l = locals()
// e_reg.addLocalEnums(l, i386regs)
//
// i386meta = [
// ("mm0", REG_ST0, 0, 64),
// ("mm1", REG_ST1, 0, 64),
// ("mm2", REG_ST2, 0, 64),
// ("mm3", REG_ST3, 0, 64),
// ("mm4", REG_ST4, 0, 64),
// ("mm5", REG_ST5, 0, 64),
// ("mm6", REG_ST6, 0, 64),
// ("mm7", REG_ST7, 0, 64),
// ("ax", REG_EAX, 0, 16),
// ("cx", REG_ECX, 0, 16),
// ("dx", REG_EDX, 0, 16),
// ("bx", REG_EBX, 0, 16),
// ("sp", REG_ESP, 0, 16),
// ("bp", REG_EBP, 0, 16),
// ("si", REG_ESI, 0, 16),
// ("di", REG_EDI, 0, 16),
//
// ("al", REG_EAX, 0, 8),
// ("cl", REG_ECX, 0, 8),
// ("dl", REG_EDX, 0, 8),
// ("bl", REG_EBX, 0, 8),
//
// ("ah", REG_EAX, 8, 8),
// ("ch", REG_ECX, 8, 8),
// ("dh", REG_EDX, 8, 8),
// ("bh", REG_EBX, 8, 8),
// ]
//
// statmetas = [
// ('CF', REG_EFLAGS, 0, 1, 'Carry Flag'),
// ('PF', REG_EFLAGS, 2, 1, 'Parity Flag'),
// ('AF', REG_EFLAGS, 4, 1, 'Adjust Flag'),
// ('ZF', REG_EFLAGS, 6, 1, 'Zero Flag'),
// ('SF', REG_EFLAGS, 7, 1, 'Sign Flag'),
// ('TF', REG_EFLAGS, 8, 1, 'Trap Flag'),
// ('IF', REG_EFLAGS, 9, 1, 'Interrupt Enable Flag'),
// ('DF', REG_EFLAGS, 10, 1, 'Direction Flag'),
// ('OF', REG_EFLAGS, 11, 1, 'Overflow Flag'),
// ('IOPL', REG_EFLAGS, 12, 2, 'I/O Privilege Level'),
// ('NT', REG_EFLAGS, 14, 1, 'Nested Task'),
// ('RF', REG_EFLAGS, 16, 1, 'Resume Flag'),
// ('VM', REG_EFLAGS, 17, 1, 'Virtual-8086 Mode'),
// ('AC', REG_EFLAGS, 18, 1, 'Alignment Check'),
// ('VIF', REG_EFLAGS, 19, 1, 'Virtual Interrupt Flag'),
// ('VIP', REG_EFLAGS, 20, 1, 'Virtual Interrupt Pending'),
// ('ID', REG_EFLAGS, 21, 1, 'ID Flag'),
// ]
//
// def getEflagsFields(regval):
// ret = []
// for name,_,shift,bits,desc in statmetas:
// ret.append( (name, regval >> shift & 1) )
// return ret
//
// e_reg.addLocalStatusMetas(l, i386meta, statmetas, 'EFLAGS')
// e_reg.addLocalMetas(l, i386meta)
//
// class i386RegisterContext(e_reg.RegisterContext):
// def __init__(self):
// e_reg.RegisterContext.__init__(self)
// self.loadRegDef(i386regs)
// self.loadRegMetas(i386meta, statmetas=statmetas)
// self.setRegisterIndexes(REG_EIP, REG_ESP, srindex=REG_EFLAGS)

use lazy_static::lazy_static;
use crate::envi::registers::{MetaRegister, RegisterContext, RegisterContextData};

const MSR_DEBUGCTL: i32 = 0x01d9;
const MSR_DEBUGCTL_LBR: i32 = 0x0001;
const MSR_DEBUGCTL_BTF: i32 = 0x0002;
const MSR_DEBUGCTL_TR: i32 = 0x0004;
const MSR_DEBUGCTL_BTS: i32 = 0x0008;
const MSR_DEBUGCTL_BTINT: i32 = 0x0010;
const MSR_DEBUGCTL_BTS_OFF_OS: i32 = 0x0020;
const MSR_DEBUGCTL_BTS_OFF_USR: i32 = 0x0040;
const MSR_SYSENTER_EIP: i32 = 0x0176;
const IA32_DS_AREA_MSR: i32 = 0x0600;

const REG_EAX: i32 = 0;
const REG_ECX: i32 = 1;
const REG_EDX: i32 = 2;
const REG_EBX: i32 = 3;
const REG_ESP: i32 = 4;
const REG_EBP: i32 = 5;
const REG_ESI: i32 = 6;
const REG_EDI: i32 = 7;
const REG_XMM0: i32 = 8;
const REG_XMM1: i32 = 9;
const REG_XMM2: i32 = 10;
const REG_XMM3: i32 = 11;
const REG_XMM4: i32 = 12;
const REG_XMM5: i32 = 13;
const REG_XMM6: i32 = 14;
const REG_XMM7: i32 = 15;
const REG_DEBUG0: i32 = 16;
const REG_DEBUG1: i32 = 17;
const REG_DEBUG2: i32 = 18;
const REG_DEBUG3: i32 = 19;
const REG_DEBUG4: i32 = 20;
const REG_DEBUG5: i32 = 21;
const REG_DEBUG6: i32 = 22;
const REG_DEBUG7: i32 = 23;
const REG_CTRL0: i32 = 24;
const REG_CTRL1: i32 = 25;
const REG_CTRL2: i32 = 26;
const REG_CTRL3: i32 = 27;
const REG_CTRL4: i32 = 28;
const REG_CTRL5: i32 = 29;
const REG_CTRL6: i32 = 30;
const REG_CTRL7: i32 = 31;
const REG_TEST0: i32 = 32;
const REG_TEST1: i32 = 33;
const REG_TEST2: i32 = 34;
const REG_TEST3: i32 = 35;
const REG_TEST4: i32 = 36;
const REG_TEST5: i32 = 37;
const REG_TEST6: i32 = 38;
const REG_TEST7: i32 = 39;
const REG_ES: i32 = 40;
const REG_CS: i32 = 41;
const REG_SS: i32 = 42;
const REG_DS: i32 = 43;
const REG_FS: i32 = 44;
const REG_GS: i32 = 45;
const REG_ST0: i32 = 46;
const REG_ST1: i32 = 47;
const REG_ST2: i32 = 48;
const REG_ST3: i32 = 49;
const REG_ST4: i32 = 50;
const REG_ST5: i32 = 51;
const REG_ST6: i32 = 52;
const REG_ST7: i32 = 53;
const REG_EFLAGS: i32 = 54;
const REG_EIP: i32 = 55;
const REG_FPSR: i32 = 56;
const REG_FPCR: i32 = 57;

lazy_static! {
	static ref I386REGS: Vec<(&'static str, i32)> = vec![
		("eax", 32), ("ecx", 32), ("edx", 32), ("ebx", 32), ("esp", 32), ("ebp", 32), ("esi", 32), ("edi", 32),
		("xmm0", 128), ("xmm1", 128), ("xmm2", 128), ("xmm3", 128), ("xmm4", 128), ("xmm5", 128), ("xmm6", 128), ("xmm7", 128),
		("debug0", 32), ("debug1", 32), ("debug2", 32), ("debug3", 32), ("debug4", 32), ("debug5", 32), ("debug6", 32), ("debug7", 32),
		("ctrl0", 32), ("ctrl1", 32), ("ctrl2", 32), ("ctrl3", 32), ("ctrl4", 32), ("ctrl5", 32), ("ctrl6", 32), ("ctrl7", 32),
		("test0", 32), ("test1", 32), ("test2", 32), ("test3", 32), ("test4", 32), ("test5", 32), ("test6", 32), ("test7", 32),
		("es", 16), ("cs", 16), ("ss", 16), ("ds", 16), ("fs", 16), ("gs", 16),
		("st0", 80), ("st1", 80), ("st2", 80), ("st3", 80), ("st4", 80), ("st5", 80), ("st6", 80), ("st7", 80),
		("eflags", 32), ("eip", 32), ("fpsr", 16), ("fpcr", 16),
	];
	static ref I386META: Vec<(&'static str, i32, i32, i32)> = vec![
		("mm0", REG_ST0, 0, 64), ("mm1", REG_ST1, 0, 64), ("mm2", REG_ST2, 0, 64), ("mm3", REG_ST3, 0, 64), ("mm4", REG_ST4, 0, 64), ("mm5", REG_ST5, 0, 64), ("mm6", REG_ST6, 0, 64), ("mm7", REG_ST7, 0, 64),
		("ax", REG_EAX, 0, 16), ("cx", REG_ECX, 0, 16), ("dx", REG_EDX, 0, 16), ("bx", REG_EBX, 0, 16), ("sp", REG_ESP, 0, 16), ("bp", REG_EBP, 0, 16), ("si", REG_ESI, 0, 16), ("di", REG_EDI, 0, 16),
		("al", REG_EAX, 0, 8), ("cl", REG_ECX, 0, 8), ("dl", REG_EDX, 0, 8), ("bl", REG_EBX, 0, 8),
		("ah", REG_EAX, 8, 8), ("ch", REG_ECX, 8, 8), ("dh", REG_EDX, 8, 8), ("bh", REG_EBX, 8, 8),
	];

	static ref STATMETAS: Vec<(&'static str, i32, i32, i32, &'static str)> = vec![
		("CF", REG_EFLAGS, 0, 1, "Carry Flag"), ("PF", REG_EFLAGS, 2, 1, "Parity Flag"), ("AF", REG_EFLAGS, 4, 1, "Adjust Flag"), ("ZF", REG_EFLAGS, 6, 1, "Zero Flag"), ("SF", REG_EFLAGS, 7, 1, "Sign Flag"), ("TF", REG_EFLAGS, 8, 1, "Trap Flag"), ("IF", REG_EFLAGS, 9, 1, "Interrupt Enable Flag"), ("DF", REG_EFLAGS, 10, 1, "Direction Flag"), ("OF", REG_EFLAGS, 11, 1, "Overflow Flag"), ("IOPL", REG_EFLAGS, 12, 2, "I/O Privilege Level"), ("NT", REG_EFLAGS, 14, 1, "Nested Task"), ("RF", REG_EFLAGS, 16, 1, "Resume Flag"), ("VM", REG_EFLAGS, 17, 1, "Virtual-8086 Mode"), ("AC", REG_EFLAGS, 18, 1, "Alignment Check"), ("VIF", REG_EFLAGS, 19, 1, "Virtual Interrupt Flag"), ("VIP", REG_EFLAGS, 20, 1, "Virtual Interrupt Pending"), ("ID", REG_EFLAGS, 21, 1, "ID Flag"),
	];
}

pub fn get_eflags_fields(regval: i32) -> Vec<(&'static str, i32)> {
	let mut ret = vec![];
	for (name, _, shift, _, _) in STATMETAS.iter() {
		ret.push((*name, regval >> shift & 1));
	}
	ret
}

pub fn get_reg_offset(regname: &str) -> i32 {
	for (i, (name, _)) in I386REGS.iter().enumerate() {
		if name.eq(&regname) {
			return i as i32;
		}
	}
	panic!("getRegOffset doesn't know about: {}", regname);
}

pub struct I386RegisterContext {
	pub regs: Vec<(String, i32)>,
	pub metas: Vec<MetaRegister>,
	pub statmetas: Vec<(String, i32, i32, i32, String)>,
	pub reg_index: i32,
	pub stack_index: i32,
	pub sr_index: i32,
	pub context_data: RegisterContextData,
}

impl I386RegisterContext {
	pub fn new() -> Self {
		let mut regs = vec![];
		let mut metas: Vec<MetaRegister> = vec![];
		let mut statmetas = vec![];
		for (name, width) in I386REGS.iter() {
			regs.push((name.to_string(), *width));
		}
		for (name, reg, shift, bits) in I386META.iter() {
			metas.push((name.to_string(), *reg, *shift, *bits).into());
		}
		for (name, reg, shift, bits, desc) in STATMETAS.iter() {
			statmetas.push((name.to_string(), *reg, *shift, *bits, desc.to_string()));
		}
		let mut context = Self {
			regs: regs.clone(),
			metas: metas.clone(),
			statmetas,
			reg_index: REG_EIP,
			stack_index: REG_ESP,
			sr_index: REG_EFLAGS,
			context_data: RegisterContextData::new(regs, metas),
		};
		context.load_reg_def(I386REGS.iter().map(|(x, width)| (x.to_string(), *width)).collect(), None);
		//context.load_reg_metas(I386META.iter().map(|(name, reg, shift, bits)| (name.to_string(), *reg, *shift, *bits)).collect(), None, Some(STATMETAS.iter().map(|(name, reg, shift, bits, desc)| (name.to_string(), *reg, *shift, *bits, desc.to_string())).collect());
		context
	}
}

impl RegisterContext for I386RegisterContext {
	fn get_register_context_data(&self) -> &RegisterContextData {
		&self.context_data
	}
	
	fn get_register_context_data_mut(&mut self) -> &mut RegisterContextData {
		&mut self.context_data
	}
}
