#![allow(dead_code, unused)]

use crate::constants::{IF_CALL, IF_RET};
use crate::memory::Memory;
use crate::monitor::EmulationMonitor;
use crate::workspace::VivWorkspace;
use std::borrow::BorrowMut;
use std::collections::HashMap;
use std::rc::Rc;

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
        self.iflags & IF_CALL == 1
    }

    pub fn is_return(&self) -> bool {
        self.iflags & IF_RET == 1
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

pub trait WorkspaceEmulator {
    /// Setup and initialize stack memory.
    /// You may call this prior to emulating instructions.
    fn init_stack_memory(&mut self, stack_size: usize);

    fn add_memory_map(&mut self, map_base: i32, size: i32, p0: &str, map: Vec<u8>);

    fn set_stack_counter(&mut self, va: i32);

    fn write_memory(&mut self, va: i32, taint_bytes: Vec<u8>);

    fn get_stack_counter(&mut self) -> Option<i32>;

    fn get_program_counter(&mut self) -> i32;

    fn get_memory_snap(&self) -> Vec<(i32, i32, Vec<String>, i32)>;

    fn set_memory_snap(&self, memory_snap: Vec<(i32, i32, Vec<String>, i32)>);

    fn set_emu_opt(&self, arch: &str, size: i32);
}

pub trait Emulator {
    fn get_vivworkspace(&mut self) -> VivWorkspace;

    fn get_func_va(&mut self) -> i32;

    fn is_emu_stopped(&self) -> bool;

    fn get_hooks(&mut self) -> Vec<String>;

    fn get_stack_map_base(&mut self) -> &mut Option<i32>;

    fn get_stack_map_mask(&mut self) -> &mut Option<i32>;

    fn get_stack_map_top(&mut self) -> &mut Option<i32>;

    fn get_stack_pointer(&mut self) -> &mut Option<i32>;
}

impl<T> WorkspaceEmulator for T
where
    T: Emulator,
{
    fn init_stack_memory(&mut self, stack_size: usize) {
        if self.get_stack_map_base().as_ref().cloned().is_none() {
            // *self.get_stack_map_mask().unwrap() =
            let mut stack_map = Vec::from(INIT_STACK_MAP);
            if stack_size != INIT_STACK_SIZE {
                stack_map = vec![0xfe; stack_size];
            }
            // Map in a memory map for the stack.
            let map_base = self.get_stack_map_base().unwrap();
            self.add_memory_map(map_base, 6, "[stack]", stack_map.clone());
            let stack_pointer = self.get_stack_pointer().unwrap();
            self.set_stack_counter(stack_pointer);
        } else {
            let existing_map_size =
                self.get_stack_map_top().unwrap() - self.get_stack_map_base().unwrap();
            let new_map_size = stack_size as i32 - existing_map_size;
            if new_map_size < 0 {
                panic!("Cannot shrink stack.");
            }
            let new_map_top = self.get_stack_map_base().unwrap();
            let new_map_base = new_map_top - new_map_size;
            let mut stack_map = Vec::new();
            for i in 0..new_map_size {
                stack_map.push(new_map_base as u8 + (i as u8 * 4));
            }
            self.add_memory_map(new_map_base, 6, "[stack]", stack_map);
        }
    }

    fn add_memory_map(&mut self, map_base: i32, size: i32, p0: &str, map: Vec<u8>) {
        todo!()
    }

    fn set_stack_counter(&mut self, va: i32) {
        todo!()
    }

    fn write_memory(&mut self, va: i32, taint_bytes: Vec<u8>) {
        todo!()
    }

    fn get_stack_counter(&mut self) -> Option<i32> {
        todo!()
    }

    fn get_program_counter(&mut self) -> i32 {
        todo!()
    }

    fn get_memory_snap(&self) -> Vec<(i32, i32, Vec<String>, i32)> {
        todo!()
    }

    fn set_memory_snap(&self, memory_snap: Vec<(i32, i32, Vec<String>, i32)>) {
        todo!()
    }

    fn set_emu_opt(&self, arch: &str, size: i32) {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub struct GenericEmulator {
    pub(crate) stack_map_base: Option<i32>,
    stack_map_mask: Option<i32>,
    stack_map_top: Option<i32>,
    stack_pointer: Option<i32>,
    workspace: VivWorkspace,
    func_va: Option<i32>,
    emustop: bool,
    hooks: HashMap<i32, i32>,
    taints: HashMap<i32, i32>,
    base: i32,
    taint_va: Vec<i16>,
    taint_offset: i16,
    taint_mask: i32,
    taint_byte: u8,
    taint_repr: HashMap<i32, i32>,
    uninit_use: HashMap<i32, i32>,
    log_write: bool,
    log_read: bool,
    path: String,
    cur_path: String,
    op: Option<i32>,
    emu_mon: Option<EmulationMonitor>,
    p_size: i32,
    safe_mem: bool,
    func_only: bool,
    strict_ops: bool,
}

impl GenericEmulator {
    pub fn new(workspace: VivWorkspace) -> Self {
        let emulator = GenericEmulator {
            stack_map_base: None,
            stack_map_mask: None,
            stack_map_top: None,
            stack_pointer: None,
            workspace,
            func_va: None,
            emustop: false,
            hooks: Default::default(),
            taints: Default::default(),
            base: 0,
            taint_va: Vec::new(),
            taint_offset: 0,
            taint_mask: 0,
            taint_byte: 0,
            taint_repr: Default::default(),
            uninit_use: Default::default(),
            log_write: false,
            log_read: false,
            path: "".to_string(),
            cur_path: "".to_string(),
            op: None,
            emu_mon: None,
            p_size: 0,
            safe_mem: false,
            func_only: false,
            strict_ops: false,
        };
        emulator
    }
    pub fn read_memory_format(&self, va: i32, taint_bytes: &str) -> Vec<i32> {
        Vec::new()
    }
}

impl Emulator for GenericEmulator {
    fn get_vivworkspace(&mut self) -> VivWorkspace {
        self.workspace.clone()
    }

    fn get_func_va(&mut self) -> i32 {
        self.func_va.as_ref().cloned().unwrap()
    }

    fn is_emu_stopped(&self) -> bool {
        self.emustop
    }

    fn get_hooks(&mut self) -> Vec<String> {
        todo!()
    }

    fn get_stack_map_base(&mut self) -> &mut Option<i32> {
        self.stack_map_base.borrow_mut()
    }

    fn get_stack_map_mask(&mut self) -> &mut Option<i32> {
        self.stack_map_mask.borrow_mut()
    }

    fn get_stack_map_top(&mut self) -> &mut Option<i32> {
        self.stack_map_top.borrow_mut()
    }

    fn get_stack_pointer(&mut self) -> &mut Option<i32> {
        self.stack_pointer.borrow_mut()
    }
}
