#![allow(dead_code, unused)]

use crate::{constants::{IF_CALL, IF_RET}, memory::Memory, monitor::EmulationMonitor, workspace::VivWorkspace};
use std::{borrow::BorrowMut, rc::Rc, collections::HashMap};
use std::sync::Arc;
use crate::envi::{ArchitectureModule, GenericArchitectureModule};
use crate::envi::archs::i386::registers::I386RegisterContext;
use crate::envi::constants::Endianess;
use crate::envi::emulator::{CallingConvention, Emulator as EnviEmulator, EmulatorData};
use crate::envi::memory::{MemoryData, MemoryDef, MemoryObject, MemoryObjectData};
use crate::envi::registers::{RegisterContext, RegisterContextData};

pub const INIT_STACK_SIZE: usize = 0x8000;
pub const INIT_STACK_MAP: [u8; INIT_STACK_SIZE] = [0xfe; INIT_STACK_SIZE];

pub trait Operand {
    /// If the given operand will dereference memory, this method must return True.
    fn is_deref(&self) -> bool {
        false
    }

    /// If the given operand represents an immediate value, this must return True.
    fn is_immed(&self) -> bool {
        false
    }

    ///  If the given operand represents a register value, this must return True.
    fn is_reg(&self) -> bool {
        false
    }

    /// If the given operand can be completly resolved without an emulator, return True.
    fn is_discrete(&self) -> bool {
        false
    }

    fn repr(&self) -> String {
        "Unknown".to_string()
    }

    /// Get the current value for the operand.  If needed, use
    /// the given emulator/workspace/trace to resolve things like
    /// memory and registers.
    /// NOTE: This API may be passed a None emu and should return what it can
    /// (or None if it can't be resolved)
    fn get_oper_value(&self, op: OpCode, emu: Option<GenericEmulator>) -> Option<i32> {
        panic!("Unimplemented.");
    }
}

pub struct DerefOper {}

impl Operand for DerefOper {
    fn is_deref(&self) -> bool {
        true
    }
}

pub struct ImmedOper {}

impl Operand for ImmedOper {
    fn is_immed(&self) -> bool {
        true
    }

    fn is_discrete(&self) -> bool {
        true
    }
}

pub struct RegisterOper {}

impl Operand for RegisterOper {
    fn is_reg(&self) -> bool {
        true
    }
}

#[derive(Clone)]
pub struct OpCode {
    pub opcode: i32,
    pub mnem: String,
    pub prefixes: i32,
    pub size: i32,
    pub opers: Vec<Rc<dyn Operand>>,
    pub repr: Option<String>,
    pub iflags: u32,
    pub va: i32,
}

impl OpCode {
    /// constructor for the basic Envi Opcode object.  Arguments as follows:
    /// opcode   - An architecture specific numerical value for the opcode
    /// mnem     - A humon readable mnemonic for the opcode
    /// prefixes - a bitmask of architecture specific instruction prefixes
    /// size     - The size of the opcode in bytes
    /// operands - A list of Operand objects for this opcode
    /// iflags   - A list of Envi (architecture independant) instruction flags (see IF_FOO)
    /// va       - The virtual address the instruction lives at (used for PC relative immediates assets...)
    /// NOTE: If you want to create an architecture spcific opcode, I'd *highly* recommend you
    /// just copy/paste in the following simple initial code rather than calling the parent
    /// constructor.  The extra
    pub fn new(
        va: i32,
        opcode: i32,
        mnem: &str,
        prefixes: i32,
        size: i32,
        operands: Vec<Rc<dyn Operand>>,
    ) -> Self {
        OpCode {
            opcode,
            mnem: mnem.to_string(),
            prefixes,
            size,
            opers: operands,
            repr: None,
            iflags: 0,
            va,
        }
    }

    pub fn is_call(&self) -> bool {
        (self.iflags & IF_CALL) != 0
    }

    pub fn is_return(&self) -> bool {
        (self.iflags & IF_RET) != 0
    }

    pub fn get_branches(&self) -> Vec<(i32, i32)> {
        vec![]
    }

    pub fn get_operands(&self) -> Option<String> {
        None
    }

    pub fn len(&self) -> usize {
        self.size as usize
    }
}

#[derive(Clone)]
pub struct WorkspaceEmulatorData {
    pub stack_map_base: Option<i32>,
    pub stack_map_mask: Option<i32>,
    pub stack_map_top: Option<i32>,
    pub stack_pointer: Option<i32>,
    pub workspace: Option<VivWorkspace>,
    pub func_va: Option<i32>,
    pub emustop: bool,
    pub hooks: HashMap<i32, Arc<Box<dyn Fn()>>>,
    pub taints: HashMap<i32, i32>,
    pub taint_va: Vec<i32>,
    pub taint_offset: i32,
    pub taint_mask: u64,
    pub taint_byte: u8,
    pub taint_repr: HashMap<i32, i32>,
    pub uninit_use: HashMap<i32, i32>,
    pub log_write: bool,
    pub log_read: bool,
    pub path: String,
    pub cur_path: String,
    pub op: Option<i32>,
    pub emu_mon: Option<EmulationMonitor>,
    pub p_size: i32,
    pub safe_mem: bool,
    pub func_only: bool,
    pub strict_ops: bool,
}

impl Default for WorkspaceEmulatorData {
    fn default() -> Self {
        let base = 0x4156000F;
        let path = "".to_string();
        WorkspaceEmulatorData {
            stack_map_base: None,
            stack_map_mask: None,
            stack_map_top: None,
            stack_pointer: None,
            workspace: None,
            func_va: None,
            emustop: false,
            hooks: Default::default(),
            taints: Default::default(),
            taint_va: [0x4156000F; 0x2000].to_vec(),
            taint_offset: 0x1000,
            taint_mask: 0xffffe000,
            taint_byte: 0xa,
            taint_repr: Default::default(),
            uninit_use: Default::default(),
            log_write: false,
            log_read: false,
            path: path.clone(),
            cur_path: path.clone(),
            op: None,
            emu_mon: None,
            p_size: 0,
            safe_mem: false,
            func_only: false,
            strict_ops: false,
        }
    }
}

pub trait WorkspaceEmulator {
    /// Setup and initialize stack memory.
    /// You may call this prior to emulating instructions.
    fn init_stack_memory(&mut self, stack_size: usize) {
        if self.get_data().stack_map_base.as_ref().cloned().is_none() {
            // *self.get_stack_map_mask().unwrap() =
            let mut stack_map = Vec::from(INIT_STACK_MAP);
            if stack_size != INIT_STACK_SIZE {
                stack_map = vec![0xfe; stack_size];
            }
            // Map in a memory map for the stack.
            let map_base = self.get_data().stack_map_base.unwrap();
            self.add_memory_map(map_base, 6, "[stack]", stack_map);
            let stack_pointer = self.get_data().stack_pointer.unwrap();
            self.set_stack_counter(stack_pointer);
        } else {
            let existing_map_size =
                self.get_data().stack_map_top.unwrap() - self.get_data().stack_map_base.unwrap();
            let new_map_size = stack_size as i32 - existing_map_size;
            if new_map_size < 0 {
                panic!("Cannot shrink stack.");
            }
            let new_map_top = self.get_data().stack_map_base.unwrap();
            let new_map_base = new_map_top - new_map_size;
            let mut stack_map = Vec::new();
            for i in 0..new_map_size {
                stack_map.push(new_map_base as u8 + (i as u8 * 4));
            }
            self.add_memory_map(new_map_base, 6, "[stack]", stack_map);
        }
    }

    fn get_data(&mut self) -> &mut WorkspaceEmulatorData;
    
    fn get_data_ref(&self) -> &WorkspaceEmulatorData;

    /// This is called by monitor to stop emulation
    fn stop_emu(&mut self) {
        self.get_data().emustop = true;
    }

    /// Retrieve a named value from th ecurrent code path context
    fn get_path_prop<T>(&self, prop: T) -> String where T: Into<String>;

    /// Set a named value which is only relevant for the current code path.
    fn set_path_prop<T>(&self, key: T,  value: T) -> Option<String> where T: Into<String>;

    /// Snap in an emulation monitor. (see EmulationMonitor doc from vivisect.monitor)
    fn set_emulation_monitor(&self, monitor: EmulationMonitor) {
        unimplemented!()
    }

    fn parse_opcode(&mut self, va: i32, arch: Option<i32>) -> Option<OpCode> {
        //self.get_data().workspace.as_ref().unwrap().parse_op_code(va)
        unimplemented!()
    }
    
    fn set_program_counter(&self, va: i32) {
        unimplemented!()
    }
    
    fn get_call_api(&self, va: i32) -> (String, String, String, i32, Vec<String>) {
        unimplemented!()
    }
    
    fn get_calling_convention(&self, name: String) -> Option<Box<dyn CallingConvention>> {
        unimplemented!()
    }

    /// Check if this was a call, and if so, do the required
    /// import emulation and such...
    fn check_call(&self, starteip: i32, endeip: i32, op: OpCode) -> bool {
        let is_call = (op.iflags & IF_CALL) != 0;
        if is_call {
            if self.get_data_ref().func_only{
                self.set_program_counter(starteip + op.len() as i32);
            }
            let api = self.get_call_api(endeip);
            let (r_type, r_name, conv_name, call_name, func_args) = api.clone();
            let call_conv = self.get_calling_convention(conv_name);
            if call_conv.as_ref().is_none() {
                return is_call;
            }
            // let argv = call_conv.unwrap().get_call_args(self, func_args.len());
            // let mut ret = None;
            // if self.get_data().emu_mon.as_ref().is_some() {
            //     match self.get_data().emu_mon.as_ref().unwrap().api_call(op, endeip, api, argv) {
            //         Ok(t) => {
            //             ret = t;
            //         },
            //         Err(_) => {
            //             self.get_data().emu_mon.as_ref().unwrap().log_anomaly(endeip, format!("API call failed: {}", call_name));
            //         }
            //     }
            // }
            // let hook = self.get_data().hooks.get(&call_name);
            // if ret.as_ref().is_none() && hook.as_ref().is_some() {
            //     let hook = hook.unwrap();
            //     hook();
            // }
        }
        is_call
    }

    fn add_memory_map(&mut self, map_base: i32, size: i32, p0: &str, map: Vec<u8>);

    fn set_stack_counter(&mut self, va: i32);

    fn write_memory(&mut self, va: i32, taint_bytes: Vec<u8>);

    fn get_stack_counter(&mut self) -> Option<i32>;

    fn get_program_counter(&mut self) -> i32;

    fn get_memory_snap(&self) -> Vec<MemoryDef>;

    fn set_memory_snap(&mut self, memory_snap: Vec<MemoryDef>);

    fn set_emu_opt(&mut self, arch: &str, size: i32);
}

pub trait Emulator: WorkspaceEmulator {
    fn get_vivworkspace(&mut self) -> VivWorkspace;

    fn get_func_va(&mut self) -> i32;

    fn is_emu_stopped(&self) -> bool;

    fn get_hooks(&mut self) -> Vec<String>;

    fn get_stack_map_base(&mut self) -> &mut Option<i32>;

    fn get_stack_map_mask(&mut self) -> &mut Option<i32>;

    fn get_stack_map_top(&mut self) -> &mut Option<i32>;

    fn get_stack_pointer(&mut self) -> &mut Option<i32>;
    
    fn stop_emu(&mut self) {
        self.get_data().emustop = true;
    }
}


#[derive(Clone)]
pub struct GenericEmulator {
    arch_module: GenericArchitectureModule,
    emulator_data: EmulatorData,
    memory_data: MemoryData,
    memory_object_data: MemoryObjectData,
    register_context: Rc<dyn RegisterContext>,
    workspace_data: WorkspaceEmulatorData,
}

impl GenericEmulator {
    pub fn new(workspace: VivWorkspace) -> Self {
        GenericEmulator {
            arch_module: Default::default(),
            emulator_data: Default::default(),
            memory_data: Default::default(),
            memory_object_data: Default::default(),
            register_context: Rc::new(I386RegisterContext::new()),
            workspace_data: WorkspaceEmulatorData {
                workspace: Some(workspace),
                ..Default::default()
            }
        }
    }
}

impl Emulator for GenericEmulator {
    fn get_vivworkspace(&mut self) -> VivWorkspace {
        self.workspace_data.workspace.clone().unwrap()
    }

    fn get_func_va(&mut self) -> i32 {
        self.workspace_data.func_va.as_ref().cloned().unwrap()
    }

    fn is_emu_stopped(&self) -> bool {
        self.workspace_data.emustop
    }

    fn get_hooks(&mut self) -> Vec<String> {
        todo!()
    }

    fn get_stack_map_base(&mut self) -> &mut Option<i32> {
        self.workspace_data.stack_map_base.borrow_mut()
    }

    fn get_stack_map_mask(&mut self) -> &mut Option<i32> {
        self.workspace_data.stack_map_mask.borrow_mut()
    }

    fn get_stack_map_top(&mut self) -> &mut Option<i32> {
        self.workspace_data.stack_map_top.borrow_mut()
    }

    fn get_stack_pointer(&mut self) -> &mut Option<i32> {
        self.workspace_data.stack_pointer.borrow_mut()
    }
}

impl WorkspaceEmulator for GenericEmulator {
    fn get_data(&mut self) -> &mut WorkspaceEmulatorData {
        &mut self.workspace_data
    }

    fn get_data_ref(&self) -> &WorkspaceEmulatorData {
        &self.workspace_data
    }

    fn get_path_prop<T>(&self, prop: T) -> String
    where
        T: Into<String>
    {
        todo!()
    }

    fn set_path_prop<T>(&self, key: T, value: T) -> Option<String>
    where
        T: Into<String>
    {
        todo!()
    }

    fn add_memory_map(&mut self, map_base: i32, size: i32, f_name: &str, map: Vec<u8>) {
        MemoryObject::add_memory_map(self, map_base, size, f_name, map.as_slice(), None);
    }

    fn set_stack_counter(&mut self, va: i32) {
        todo!()
    }

    fn write_memory(&mut self, va: i32, taint_bytes: Vec<u8>) {
        MemoryObject::write_memory(self, va, taint_bytes.as_slice(), None);
    }

    fn get_stack_counter(&mut self) -> Option<i32> {
        todo!()
    }

    fn get_program_counter(&mut self) -> i32 {
        RegisterContext::get_program_counter(self)
    }

    fn get_memory_snap(&self) -> Vec<MemoryDef> {
        MemoryObject::get_memory_snap(self)
    }

    fn set_memory_snap(&mut self, memory_snap: Vec<MemoryDef>) {
       MemoryObject::set_memory_snap(self, memory_snap);
    }

    fn set_emu_opt(&mut self, arch: &str, size: i32) {
        todo!()
    }
}

impl RegisterContext for GenericEmulator {
    fn get_register_context_data(&self) -> &RegisterContextData {
        self.register_context.get_register_context_data()
    }

    fn get_register_context_data_mut(&mut self) -> &mut RegisterContextData {
        Rc::get_mut(&mut self.register_context)
            .unwrap()
            .get_register_context_data_mut()
    }
}

impl MemoryObject for GenericEmulator {
    fn get_memory_object_data_mut(&mut self) -> &mut MemoryObjectData {
        &mut self.memory_object_data
    }

    fn get_memory_object_data(&self) -> &MemoryObjectData {
        &self.memory_object_data
    }
}

impl crate::envi::memory::Memory for GenericEmulator {
    fn get_memory_data(&self) -> &MemoryData {
        &self.memory_data
    }

    fn get_endian(&self) -> Endianess {
        EnviEmulator::get_emulator_data(self).endian.clone()
    }

    fn set_endian(&mut self, endian: Endianess) {
        EnviEmulator::get_emulator_data_mut(self).endian = endian;
    }

    fn set_mem_architecture(&mut self, arch: i32) {
        EnviEmulator::get_arch_module_mut(self, None).get_data_mut().arch_id = arch;
    }

    fn get_pointer_size(&self) -> i32 {
        todo!()
    }

    fn read_memory(&self, addr: i32, size: i32) -> Option<Vec<u8>> {
        MemoryObject::read_memory(self, addr, size, None).ok()
    }

    fn write_memory(&mut self, addr: i32, data: &[u8]) {
        MemoryObject::write_memory(self, addr, data, None);
    }

    fn protect_memory(&self, addr: i32, size: i32, perms: i32) {
        todo!()
    }

    fn allocate_memory(&mut self, size: i32, perms: i32, suggest_addr: Option<i32>) {
        MemoryObject::allocate_memory(self, size, perms, suggest_addr, None, None, None);
    }

    fn add_memory_map(&mut self, map_va: i32, perms: i32, f_name: &str, data: Option<&[u8]>, align: Option<i32>) {
        MemoryObject::add_memory_map(self, map_va, perms, f_name, data.unwrap_or_default(), align);
    }

    fn get_memory_maps(&self) -> Vec<(i32, i32, i32, Option<String>)> {
        MemoryObject::get_memory_maps(self)
    }
}

impl EnviEmulator for GenericEmulator {
    fn get_emulator_data_mut(&mut self) -> &mut EmulatorData {
        &mut self.emulator_data
    }

    fn get_emulator_data(&self) -> &EmulatorData {
        &self.emulator_data
    }

    fn get_arch_module(&self, arch: Option<i32>) -> &GenericArchitectureModule {
        &self.arch_module
    }

    fn get_arch_module_mut(&mut self, arch: Option<i32>) -> &mut GenericArchitectureModule {
        &mut self.arch_module
    }

    fn execute_op_code(&mut self, op: crate::envi::operands::OpCode) -> Result<(), crate::error::Error> {
        todo!()
    }
}
