#![allow(unused)]
use std::rc::Rc;
use log::warn;
use crate::envi::constants::{BR_DEREF, BR_FALL, IF_CALL, IF_RET};
use crate::envi::emulator::Emulator;
use crate::envi::memcanvas::MemoryCanvas;
use crate::error::Error::FuncNotImplemented;
use crate::envi::Result;

pub trait Operand{
    fn is_deref(&self) -> bool {
        false
    }

    /// If the given operand represents an immediate value, this must return `true`.
    fn is_immed(&self) -> bool {
        false
    }

    /// If the given operand represents a register value, this must return `true`.
    fn is_reg(&self) -> bool {
        false
    }

    /// If the given operand can be completly resolved without an emulator, return `true`.
    fn is_discrete(&self) -> bool {
        false
    }

}

/// These are the expected methods needed by any implemented operand object
/// attached to an envi Opcode.  This does *not* have a constructor of it's
/// pwn on purpose to cut down on memory use and constructor CPU cost.
impl dyn Operand  {
    /// Get the current value for the operand.  If needed, use
    /// the given emulator/workspace/trace to resolve things like
    /// memory and registers.
    ///
    /// NOTE: This API may be passed a None emu and should return what it can
    /// (or None if it can't be resolved)
    pub fn get_oper_value(&self, _op: OpCode, _emulator: Option<&dyn Emulator>) -> Result<Option<i32>> {
        Err(FuncNotImplemented("get_oper_value".to_string()))
    }

    /// Set the current value for the operand.  If needed, use
    /// the given emulator/workspace/trace to assign things like
    /// memory and registers.
    pub fn set_oper_value(&mut self, _op: OpCode, _emulator: Option<&dyn Emulator>, _val: i32) -> Result<()> {
        warn!("set_oper_value not implemented");
        Err(FuncNotImplemented("set_oper_value".to_string()))
    }

    /// If the given operand will dereference memory, this method must return `true`.
    
    /// If the operand is a "dereference" operand, this method should use the
    /// specified op/emu to resolve the address of the dereference.
    ///
    /// NOTE: This API may be passed a None emu and should return what it can
    /// (or None if it can't be resolved)
    pub fn get_oper_addr(&self, _op: OpCode, _emulator: Option<&dyn Emulator>) -> Result<Option<i32>> {
        warn!("get_oper_addr not implemented");
        Err(FuncNotImplemented("get_oper_addr".to_string()))
    }

    /// Used by the Opcode class to get a humon readable string for this operand.
    fn repr(&self, _op: &OpCode) -> String {
        "Unknown".to_string()
    }

    /// Used by the opcode class when rendering to a memory canvas.
    fn render(&self, mcanv: &Rc<dyn MemoryCanvas>, op: OpCode, _idx: i32) {
        mcanv.add_text(self.repr(&op), None);
    }
}

pub struct DerefOper;

impl Operand for DerefOper {
    fn is_deref(&self) -> bool {
        true
    }
}

pub struct ImmedOper;

impl Operand for ImmedOper {
    fn is_immed(&self) -> bool {
        true
    }

    fn is_discrete(&self) -> bool {
        true
    }
}

pub struct RegisterOper;

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
    pub prefix_names: Vec<(i32, String)>,
    pub size: i32,
    pub opers: Vec<Rc<dyn Operand>>,
    pub repr: Option<String>,
    pub iflags: i32,
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
        iflags: Option<i32>
    ) -> Self {
        OpCode {
            opcode,
            mnem: mnem.to_string(),
            prefixes,
            prefix_names: vec![],
            size,
            opers: operands,
            repr: None,
            iflags: iflags.unwrap_or(0),
            va,
        }
    }

    pub fn is_call(&self) -> bool {
        self.iflags & IF_CALL == 1
    }

    pub fn is_return(&self) -> bool {
        self.iflags & IF_RET == 1
    }

    /// Determines the targets of call/branch instructions.  Fall throughs are
    /// not considered as targets. Deref branches are resolved.
    /// 
    /// Returns [(bva, bflags),...]
    /// 
    /// addr can be `None` in cases where the branch target cannot be computed.
    /// (for example, if BR_DEREF flag is set and cannot read the memory)
    /// Once resolved, the BR_DEREF flag is removed from branch flags.
    pub fn get_targets(&self, emulator: Option<&dyn Emulator>) -> Vec<(Option<i32>, i32)> {
        let mut remote_branches = vec![];
        for (b_va, mut b_flags) in self.get_branches(emulator.as_ref().cloned()) {
            if b_flags & BR_FALL == 1 {
                continue;
            }
            let mut my_bva = Some(b_va);
            if b_va == 1 && b_flags & BR_DEREF == 1 {
                if let Some(emu) = emulator {
                    my_bva = Some(emu.read_memory_format(b_va, "<P")[0]);
                    b_flags &= !BR_DEREF;
                } else { 
                    my_bva = None;
                }
            }
            remote_branches.push((my_bva, b_flags));
        }
        remote_branches
    }

    /// Operand generator, yielding an `(oper-index, operand)` tuple from this
    /// Opcode... but only for operands which make sense for XREF analysis.
    /// Override when architecture makes use of odd operands like the program
    /// counter, which returns a real value even without an emulator.
    pub fn gen_ref_opers(&self, _emulator: Option<&dyn Emulator>) -> impl Iterator<Item=(i32, &Rc<dyn Operand>)> {
        self.opers.iter().enumerate().map(|(idx, oper)| {
            (idx as i32, oper)
        })
    }

    /// Return a list of tuples.  Each tuple contains the target VA of the
    /// branch, and a possible set of flags showing what type of branch it is.
    /// 
    /// See the BR_FOO types for all the supported envi branch flags....
    /// Example: for bva,bflags in op.getBranches():
    pub fn get_branches(&self, _emulator: Option<&dyn Emulator>) -> Vec<(i32, i32)> {
        vec![]
    }

    pub fn get_operands(&self) -> &Vec<Rc<dyn Operand>> {
        &self.opers
    }

    pub fn get_oper_value(&self, idx: i32, emu: Option<&dyn Emulator>) -> Result<Option<i32>> {
        self.opers[idx as usize].get_oper_value(self.clone(), emu)
    }

    pub fn get_prefix_name(&self) -> String {
        let mut ret = vec![];
        for (byte, name) in self.prefix_names.iter() {
            if self.prefixes & byte == 1 {
                ret.push(name.clone());
            }
        }
        ret.join(" ")
    }

    pub fn repr(&self) -> String {
        let pfx = self.get_prefix_name();
        format!("{}: {} {} ", pfx, self.mnem, self.opers.iter().map(|x| x.repr(self)).collect::<Vec<String>>().join(", "))
    }
    
    pub fn render(&self, mcanv: &Rc<dyn MemoryCanvas>) {
        mcanv.add_text(self.repr(), None);
    } 

    pub fn len(&self) -> usize {
        self.size as usize
    }
}