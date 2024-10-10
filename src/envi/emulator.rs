use std::cmp::max;
use std::rc::Rc;
use crate::envi::constants::{CC_REG, CC_STACK, CC_STACK_INF, Endianess};
use crate::envi::ArchitectureModule;
use crate::envi::registers::RegisterContext;
use crate::envi::memory::{MemoryDef, MemoryObject};
use crate::envi::operands::OpCode;
use crate::error::Error::{Generic, UnknownCallingConvention};
use crate::envi::Result;

#[derive(Clone)]
pub struct EmulatorData {
    pub endian: Endianess,
    pub metadata: std::collections::HashMap<String, i32>,
    pub emu_opts: std::collections::HashMap<String, String>,
    pub emu_segments: Vec<(i32, i32)>,
    pub emu_calling_conventions: std::collections::HashMap<String, Rc<dyn CallingConvention>>,
    pub emu_opts_doc: std::collections::HashMap<String, String>,
    pub op_methods: std::collections::HashMap<String, String>,
}

pub trait Emulator: RegisterContext + MemoryObject{

    fn get_emulator_data_mut(&mut self) -> &mut EmulatorData;

    fn get_emulator_data(&self) -> &EmulatorData;
    
    fn get_arch_module(&self, arch: Option<i32>) -> &Rc<dyn ArchitectureModule>;

    /// This is the core method for an emulator to do any running of instructions and
    /// setting of the program counter should an instruction require that.
    fn execute_op_code(&mut self, op: OpCode) -> Result<()>;
}

/// The emulator should be able to
/// be extended for the architecutures which are included
/// in the envi framework.  You *must* mix in
/// an instance of your architecture abstraction module.
///
/// (NOTE: Most users will just use an arch mod and call getEmulator())
///
/// The intention is for "light weight" emulation to be
/// implemented mostly for user-space emulation of
/// protected mode execution.
impl<'a> dyn Emulator + 'a {
    
    /// Initialize an emulator option used by the emulator type.
    /// Arch specific options should begin with <arch>: and platform
    /// options should begin with <platform>:
    fn init_emu_opts(&mut self, opt: &str, def_val: &str, doc: &str) {
        let data = self.get_emulator_data_mut();
        data.emu_opts.insert(opt.to_string(), def_val.to_string());
        data.emu_opts_doc.insert(opt.to_string(), doc.to_string());
    }

    fn set_emu_opt(&mut self, key: &str, val: &str) {
        let data = self.get_emulator_data_mut();
        data.emu_opts.insert(key.to_string(), val.to_string());
    }

    fn get_emu_opt(&self, key: &str) -> Option<&str> {
        let data = self.get_emulator_data();
        data.emu_opts.get(key).map(|s| s.as_str())
    }

    fn set_endian(&mut self, endian: Endianess) {
        let data = self.get_emulator_data_mut();
        data.endian = endian;
    }

    fn get_endian(&self) -> Endianess{
        let data = self.get_emulator_data();
        data.endian.clone()
    }

    fn get_meta(&self, name: &str, default: Option<i32>) -> i32 {
        let data = self.get_emulator_data();
        data.metadata
            .get(name)
            .map_or_else(
                || default.unwrap_or(0), 
                |val| *val
            )
    }
    
    fn set_meta(&mut self, name: &str, value: i32) {
        let data = self.get_emulator_data_mut();
        data.metadata.insert(name.to_string(), value);
    }
    
    /// Return the data needed to "snapshot" this emulator.  For most
    /// archs, this method will be enough (it takes the memory object,
    /// and register values with it)
    fn get_emu_snap(&self) -> (Vec<i32>, Vec<MemoryDef>) {
        let regs = self.get_register_snap();
        let mem = self.get_memory_snap();
        (regs, mem)
    }
    
    fn set_emu_snap(&mut self, snap: (Vec<i32>, Vec<MemoryDef>)) {
        let (regs, mem) = snap;
        self.set_register_snap(regs);
        self.set_memory_snap(mem);
    }

    /// Utility function to try something with an emulator, and then revert it.
    /// If we fail to get a valid snap, we raise a base EmuException. Otherwise,
    /// we yield out the snap we received.
    ///
    /// On close, we try to rollback the emulator using the snap.
    fn snap(&mut self) -> (Vec<i32>, Vec<MemoryDef>) {
        let snap  = self.get_emu_snap();
        self.set_emu_snap(snap.clone());
        snap
    }

    /// Run the emulator until "something" happens.
    /// (breakpoint, segv, syscall, etc...)
    ///
    /// Set stepcount in order to run that many instructions before pausing emulation
    fn run(&mut self, step_count: Option<i32>) -> Result<()> {
        if let Some(count) = step_count {
            for _ in 0..count {
                self.stepi()?;
            }
        } else {
            loop {
                self.stepi()?;
            }
        }
        Ok(())
    }

    fn stepi(&mut self) -> Result<()> {
        let pc = self.get_program_counter();
        let op = MemoryObject::parse_op_code(self, pc, None)?;
        self.execute_op_code(op)
    }

    fn get_segment_info(&self, op: OpCode) -> (i32, i32) {
        let indx = self.get_segment_index(op);
        let data = self.get_emulator_data();
        data.emu_segments[indx as usize]
    }

    /// The *default* segmentation is none (most arch's will over-ride).
    /// This method may be implemented to return a segment index based on either
    /// emulator state or properties of the particular instruction in question.
    fn get_segment_index(&self, _op: OpCode) -> i32 {
        0
    }

    /// Set a base and size for a given segment index
    fn set_segment_info(&mut self, indx: i32, base: i32, size: i32) {
        let data = self.get_emulator_data_mut();
        if (data.emu_segments.len() as i32 - indx) == 0 {
            data.emu_segments.push((base, size));
            return;
        }
        data.emu_segments[indx as usize] = (base, size);
    }

    /// Return the value for the operand at index idx for
    /// the given opcode reading memory and register states if necessary.
    /// 
    /// In partially-defined emulation, this may return None
    fn get_oper_value(&self, op: OpCode, indx: i32) -> Result<Option<i32>> {
        let oper = op.get_operands()[indx as usize].clone();
        oper.get_oper_value(op, None)
    }

    /// Set the value of the target operand at index idx from
    /// opcode op.
    /// (obviously OM_IMMEDIATE *cannot* be set)
    fn set_oper_value(&self, op: OpCode, indx: i32, value: i32) -> Result<()> {
        let mut oper = op.get_operands()[indx as usize].clone();
        Rc::get_mut(&mut oper).unwrap().set_oper_value(op, Some(self), value)
    }

    /// Emulator implementors can implement this method to allow
    /// analysis modules a platform/architecture independant way
    /// to get stack/reg/whatever args.
    ///
    /// Usage: getCallArgs(3, "stdcall") -> (0, 32, 0xf00)
    fn get_call_args(&mut self, count: i32, calling_convention: String) -> Result<Vec<i32>> {
        let data = self.get_emulator_data().clone();
        if let Some(cc) = data.emu_calling_conventions.get(&calling_convention) {
            return Ok(cc.get_call_args(self, count));
        }
        Err(UnknownCallingConvention(calling_convention))
    }

    /// Emulator implementors can implement this method to allow
    /// analysis modules a platform/architecture independant way
    /// to set a function return value. (this should also take
    /// care of any argument cleanup or other return time tasks
    /// for the calling convention)
    fn exec_call_return(&self, value: i32, calling_convention: String, argc: Option<i32>) -> Result<i32>{
        let data = self.get_emulator_data();
        if let Some(cc) = data.emu_calling_conventions.get(&calling_convention) {
            return Ok(cc.exec_call_return(self, value, argc))
        }
        Err(UnknownCallingConvention(calling_convention))
    }
    
    fn add_calling_convention(&mut self, name: String, cc: Rc<dyn CallingConvention>) {
        let data = self.get_emulator_data_mut();
        data.emu_calling_conventions.insert(name, cc);
    }
    
    fn has_calling_convention(&self, name: &str) -> bool {
        let data = self.get_emulator_data();
        data.emu_calling_conventions.contains_key(name)
    }
    
    fn get_calling_convention(&self, name: &str) -> Option<&Rc<dyn CallingConvention>> {
        let data = self.get_emulator_data();
        data.emu_calling_conventions.get(name)
    }
    
    fn get_calling_conventions(&self) -> Vec<String> {
        let data = self.get_emulator_data();
        data.emu_calling_conventions.keys().map(|s| s.clone()).collect()
    }
    
    /// Returns the value of the bytes at the "addr" address, given the size (currently, power of 2 only)
    fn read_mem_value(&self, va: i32, size: i32) -> Result<Option<Vec<i32>>> {
        if let Ok(data) = MemoryObject::read_memory(self, va, size, None){
            if data.len() as i32 != size {
                return Err(Generic(format!("Read gave wrong length at {} (va: {} wanted {} got {})", self.get_program_counter(), va, size, data.len() as i32)))
            }
           // parse_bytes()
        }
        Ok(None)
    }
}


#[derive(Clone, Debug)]
pub struct CallingConventionData {
    pub pad: i32,
    pub align: i32,
    pub delta: i32,
    pub flags: i32,
    pub arg_def: Vec<(i32, i32)>,
    pub ret_val_def: (i32, i32),
    pub ret_addr_def: (i32, i32),
}

impl Default for CallingConventionData {
    fn default() -> CallingConventionData {
        CallingConventionData {
            pad: 0,
            align: 4,
            delta: 0,
            flags: 0,
            arg_def: vec![],
            ret_val_def: (CC_STACK, 0),
            ret_addr_def: (CC_STACK, 0),
        }
    }
}

pub trait CallingConvention {
    fn get_data(&self) -> &CallingConventionData;

    /// Returns the number of stack arguments.
    fn get_num_stack_args(&self, _emulator: Option<&dyn Emulator>, argc: i32) -> i32 {
        let data = self.get_data();
        let rargs = data.arg_def
            .iter()
            .filter(|(key, _val)| *key == CC_REG)
            .collect::<Vec<_>>();
        max(argc - rargs.len() as i32, 0)
    }

    /// Returns the number of bytes from RET to the first Stack Arg
    fn get_stack_arg_offset(&self, _emulator: Option<&dyn Emulator>, _argc: i32) -> i32 {
        let data = self.get_data();
        data.pad + data.align
    }

    /// Returns a list of the arguments passed to the function.
    /// 
    /// Expects to be called at call/jmp to function entrypoint.
    fn get_precall_args(&self, emulator: &dyn Emulator, mut argc: i32) -> Vec<i32> {
        let data = self.get_data();
        let mut args = vec![];
        let mut sp = emulator.get_stack_counter();
        sp += data.pad;
        for (arg_type, arg_val) in data.arg_def.iter() {
            if argc <= 0 {
                break;
            }
            match *arg_type {
                CC_REG => {
                    args.push(emulator.get_register(*arg_val));
                    argc -= 1;
                },
                CC_STACK => {
                    args.push(emulator.read_memory_format(sp, "<P")[0]);
                    argc -= 1;
                    sp += data.align;
                },
                CC_STACK_INF=> {
                    let mut values = emulator.read_memory_format(sp, format!("<{argc}P").as_str());
                    args.append(&mut values);
                    argc -= values.len() as i32;
                    if argc != 0 {
                        panic!("Wrong number of args from read_memory_format!");
                    }
                },
                _ => {
                    panic!("Unknown argument type: {}", arg_type);
                }
            }
        }
        args
    }
    
    fn set_precall_args(&self, emulator: &mut dyn Emulator, mut args: Vec<i32>) {
        let data = self.get_data();
        let mut argc = args.len() as i32;
        let mut cur_arg = 0;
        let mut sp = emulator.get_stack_counter();
        sp += data.pad;
        for (arg_type, mut arg_val) in data.arg_def.iter() {
            if argc <= 0 {
                break;
            }
            match *arg_type {
                CC_REG => {
                    emulator.set_register(arg_val, args[cur_arg]);
                    cur_arg += 1;
                },
                CC_STACK => {
                    emulator.write_memory_format(sp, "<P".to_string(), &[args[cur_arg]]);
                    argc -= 1;
                    cur_arg += 1;
                    sp += data.align;
                },
                CC_STACK_INF => {
                    arg_val -= data.align;
                    emulator.write_memory_format(sp, format!("<{argc}P"), &args[cur_arg..]);
                    argc -= args[cur_arg..].len() as i32;
                    if argc != 0 {
                        panic!("Wrong number of args from write_memory_format!");
                    }
                },
                _ => {
                    panic!("Unknown argument type: {}", arg_type);
                }
            }
        }
    }

    ///Returns a list of the arguments passed to the function.
    ///
    ///Expects to be called at the function entrypoint.
    fn get_call_args(&self, emulator: &mut dyn Emulator, argc: i32) -> Vec<i32> {
        let data = self.get_data();
        let sp = emulator.get_stack_counter();
        emulator.set_stack_counter(sp + data.delta);
        let args = self.get_precall_args(emulator, argc);
        emulator.set_stack_counter(sp);
        args
    }

    /// Returns the return address.
    /// 
    /// Expects to be called at the function entrypoint.
    fn get_return_address(&self, emulator: &dyn Emulator) -> i32 {
        let data = self.get_data();
        let sp = emulator.get_stack_counter();
        emulator.read_memory_format(sp + data.ret_addr_def.1, "<P")[0]
    }
    
    fn exec_call_return(&self, emulator: &dyn Emulator, value: i32, argc: Option<i32>) -> i32 {
        let data = self.get_data();
        let sp = emulator.get_stack_counter();
        let ret_addr = self.get_return_address(emulator);
        let mut sp = sp + data.ret_val_def.1;
        if let Some(count) = argc {
            sp += count * data.align;
        }
        emulator.write_memory_format(sp, "<P".to_string(), &[value]);
        ret_addr
    }
}

