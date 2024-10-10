use std::collections::HashMap;
use std::rc::Rc;
use crate::envi::emulator::Emulator;
use crate::envi::constants::Endianess;
use crate::envi::operands::OpCode;
use crate::envi::registers::RegisterContext;
use crate::error::Error::ArchNotImplemented;

pub mod constants;
pub mod utils;
pub mod archs;
pub mod operands;
pub mod emulator;
pub mod memcanvas;
pub mod registers;
pub mod memory;

pub(in crate::envi) type Result<T> = std::result::Result<T, crate::error::Error>;



pub trait ArchitectureModuleData {
    fn get_arch_id(&self) -> i32;
    fn get_arch_name(&self) -> String;
    fn get_arch_maxinst(&self) -> i32;
    fn get_arch_bad_op_bytes(&self) -> Vec<Vec<u8>>;
    fn get_endian(&self) -> Endianess;
    fn get_bad_ops(&mut self) -> &mut Vec<OpCode>;
    
    fn get_default_call(&self) -> Option<i32>;
    fn get_plat_default_calls(&self) -> HashMap<&str, i32>;
}


/// An architecture module implements methods to deal
/// with the creation of envi objects for the specified
/// architecture.
pub trait ArchitectureModule {
    fn get_data_mut(&mut self) -> &mut dyn ArchitectureModuleData;
    
    fn get_data(&self) -> &dyn ArchitectureModuleData;

    /// Return the envi ARCH_FOO value for this arch.
    fn get_arch_id(&self) -> i32 {
        self.get_data().get_arch_id()
    }

    /// Get the "humon" readable name for the arch implemented
    /// in this module.
    fn get_arch_name(&self) -> String {
        self.get_data().get_arch_name()
    }
    
    /// Every architecture stores numbers either Most-Significant-Byte-first (MSB)
    /// or Least-Significant-Byte-first (LSB).  Most modern architectures are
    /// LSB, however many legacy systems still use MSB architectures.
    fn get_endian(&self) -> Endianess {
        let data = self.get_data();
        let endian = data.get_endian();
        endian
    }

    fn get_arch_maxinst(&self) -> i32 {
        self.get_data().get_arch_maxinst()
    }
    
    /// Return a string of the byte sequence which corresponds to
    /// a breakpoint (if present) for this architecture.
    fn arch_get_break_instr(&self) -> Result<()> {
        Err(ArchNotImplemented("arch_get_break_instr".to_string()))
    }
    
    /// Return a string of the byte sequence which corresponds to
    /// a no-op (if present) for this architecture.
    fn arch_get_nop_instr(&self) -> Result<()> {
        Err(ArchNotImplemented("arch_get_nop_instr".to_string()))
    }
    
    /// Return an initialized register context object for the architecture.
    fn arch_get_reg_ctx(&self) -> Result<Rc<dyn RegisterContext>> {
        Err(ArchNotImplemented("arch_get_reg_ctx".to_string()))
    }
    
    /// Parse an architecture specific opcode from the bytes provided.
    /// This method should return an OpCode object.
    fn arch_parse_opcode(&self, _bytes: Vec<u8>, _offset: Option<i32>, _va: Option<i32>) -> Result<OpCode> {
        Err(ArchNotImplemented("arch_parse_opcode".to_string()))
    }
    
    /// Returns a tuple of tuples of registers for different register groups.
    /// If not implemented for an architecture, returns a single group with
    /// all non-meta registers.
    /// 
    /// Example:
    /// ``` [ ('all', ['eax', 'ebx', ...] ), ...]```
    fn arch_get_register_groups(&self) -> Result<Vec<(&'static str, Vec<String>)>> {
        let reg_ctx = self.arch_get_reg_ctx()?;
        let allr = reg_ctx.get_register_names();
        Ok(vec![("all", allr)])
    }
    
    /// Can modify the VA and context based on architecture-specific info.
    /// Default: return the same va, info
    /// 
    /// This hook allows an architecture to correct VA and Architecture, such
    /// as is necessary for ARM/Thumb.
    /// 
    /// "info" should be a dictionary with the `{'arch': ARCH_FOO}`
    /// 
    /// eg.  for ARM, the ARM disassembler would hand in
    /// `{'arch': ARCH_ARMV7}`
    /// 
    /// and if va is odd, that architecture's implementation would return
    /// `((va & -2), {'arch': ARCH_THUMB})`
    fn arch_modify_func_addr(&self, va: i32, info: HashMap<String, i32>) -> (i32, HashMap<String, i32>) {
        (va, info)
    }

    /// Returns a potentially modified set of (tova, reftype, rflags).
    /// Default: return the same (tova, reftype, rflags)
    /// 
    /// This hook allows an architecture to modify an Xref before it's set,
    /// which can be helpful for ARM/Thumb.
    fn arch_modify_xref_addr(&self, to_va: i32, ref_type: i32, r_flags: i32) -> (i32, i32, i32) {
        (to_va, ref_type, r_flags)
    }

    /// Returns a list of opcodes which are indicators of wrong disassembly.
    /// `bytes` is `None` to use the architecture default, or can be a custom list.
    fn arch_get_bad_ops(&mut self, bytes: Option<Vec<Vec<u8>>>) -> Result<Vec<OpCode>> {
        if bytes.as_ref().is_none() && self.get_data_mut().get_bad_ops().len() > 0 {
            return Ok(self.get_data_mut().get_bad_ops().clone());
        }
        *self.get_data_mut().get_bad_ops() = vec![];
        for bad_bytes in bytes.unwrap().iter() {
            let op_code = self.arch_parse_opcode(bad_bytes.clone(), None, None)?;
            self.get_data_mut().get_bad_ops().push(op_code);
        }
        Ok(self.get_data_mut().get_bad_ops().clone())
    }
    
    /// Return a default instance of an emulator for the given arch.
    fn get_emulator(&self) -> Result<&Rc<dyn Emulator>> {
        Err(ArchNotImplemented("get_emulator".to_string()))
    }
    
    /// Get the size of a pointer in memory on this architecture.
    fn get_pointer_size(&self) -> Result<i32> {
        Err(ArchNotImplemented("get_pointer_size".to_string()))
    }
    
    /// Return a string representation for a pointer on this arch
    fn get_pointer_string(&self, _va: i32) -> Result<String> {
        Err(ArchNotImplemented("get_pointer_string".to_string()))
    }
    
    fn get_arch_default_call(&self) -> Option<i32> {
        self.get_data().get_default_call()
    }
    
    fn get_plat_default_call(&self, platform: &str) -> Option<i32> {
        self.get_data().get_plat_default_calls().get(platform).cloned()
    }
    
    fn arch_get_pointer_alignment(&self) -> i32 {
        1
    }
}