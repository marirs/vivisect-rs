use std::collections::HashMap;
use crate::envi::constants::RMETA_NMASK;
use crate::error::Error::InvalidRegisterName;
use crate::envi::Result;

#[derive(Clone, Debug)]
pub struct MetaRegister {
    pub name: String,
    pub index: i32,
    pub size: i32,
    pub shift_offset: i32,
}

impl Into<MetaRegister> for (String, i32, i32, i32) {
    fn into(self) -> MetaRegister {
        MetaRegister {
            name: self.0,
            index: self.1,
            size: self.2,
            shift_offset: self.3,
        }
    }
}

#[derive(Clone, Debug)]
pub struct StatusMetaRegister {
    pub name: String,
    pub index: i32,
    pub size: i32,
    pub shift_offset: i32,
    pub description: String
}

#[derive(Clone, Debug, Default)]
pub struct RegisterContextData {
    _rctx_vals: Vec<i32>,
    _rctx_dirty: bool,
    _rctx_pc_index: i32,
    _rctx_sp_index: i32,
    _rctx_sr_index: Option<i32>,
    _rctx_reg_def: Vec<(String, i32)>,
    _rctx_reg_metas: Vec<MetaRegister>,
    _rctx_stat_metas: Option<Vec<StatusMetaRegister>>,
    _rctx_names: HashMap<String, i32>,
    _rctx_widths: Vec<i32>,
    _rcts_vals: Vec<i32>,
    _rctx_masks: Vec<i32>,
    _rctx_ids: HashMap<i32, String>,
}

impl RegisterContextData {
    pub fn new(reg_defs: Vec<(String, i32)>, reg_metas: Vec<MetaRegister>) -> Self {
        RegisterContextData {
            _rctx_vals: vec![],
            _rctx_dirty: false,
            _rctx_pc_index: 0,
            _rctx_sp_index: 0,
            _rctx_sr_index: None,
            _rctx_reg_def: reg_defs,
            _rctx_reg_metas: reg_metas,
            _rctx_stat_metas: None,
            _rctx_names: HashMap::new(),
            _rctx_widths: vec![],
            _rcts_vals: vec![],
            _rctx_masks: vec![],
            _rctx_ids: HashMap::new(),
        }
    }
}


pub trait RegisterContext{
    fn get_register_context_data(&self) -> &RegisterContextData;
    
    fn get_register_context_data_mut(&mut self) -> &mut RegisterContextData;

    /// Use this to bulk save off the register state.
    fn get_register_snap(&self) -> Vec<i32> {
        self.get_register_context_data()._rctx_vals.clone()
    }

    /// Use this to bulk restore the register state.
    ///
    /// NOTE: This may only be used under the assumption that the
    /// RegisterContext has been initialized the same way
    /// (like context switches in tracers, or emulaction snaps)
    fn set_register_snap(&mut self, regs: Vec<i32>) {
        self.get_register_context_data_mut()._rctx_vals = regs;
    }

    /// Returns true if registers in this context have been modififed
    /// since their import.
    fn is_dirty(&self) -> bool {
        self.get_register_context_data()._rctx_dirty
    }
    
    fn set_is_dirty(&mut self, dirty: bool) {
        self.get_register_context_data_mut()._rctx_dirty = dirty;
    }
    
    fn set_register_indexes(&mut self, pc_index: i32, sp_index: i32, sr_index: Option<i32>) {
        let data = self.get_register_context_data_mut();
        data._rctx_pc_index = pc_index;
        data._rctx_sp_index = sp_index;
        data._rctx_sr_index = sr_index;
    }

    /// Load a register definition.  A register definition consists
    /// of a list of tuples with the following format:
    /// (regname, regwidth)
    ///
    /// NOTE: All widths in envi RegisterContexts are in bits.
    fn load_reg_def(&mut self, reg_def: Vec<(String, i32)>, defval: Option<i32>) {
        let data = self.get_register_context_data_mut();
        let defal = defval.unwrap_or(0);
        data._rctx_reg_def = reg_def.clone();
        data._rctx_vals = vec![];
        data._rctx_names = HashMap::new();
        data._rctx_ids = HashMap::new();
        data._rctx_widths = vec![];
        data._rcts_vals = vec![];
        data._rctx_masks = vec![];
        for (i, (name, width)) in reg_def.iter().enumerate() {
            data._rctx_names.insert(name.clone(), i as i32);
            data._rctx_ids.insert(i as i32, name.clone());
            data._rctx_widths.push(*width);
            data._rctx_masks.push((2i32.pow(*width as u32)) - 1);
            data._rcts_vals.push(defal);
        }
    }
    
    fn get_reg_def(&self) -> Vec<(String, i32)> {
        self.get_register_context_data()._rctx_reg_def.clone()
    }

    /// Load a set of defined "meta" registers for this architecture.  Meta
    /// registers are defined as registers who exist as a subset of the bits
    /// in some other "real" register. The argument metas is a list of tuples
    /// with the following format:
    /// (regname, regidx, reg_shift_offset, reg_width)
    /// The given example is for the AX register in the i386 subsystem
    /// regname: "ax"
    /// reg_shift_offset: 0
    /// reg_width: 16
    ///
    /// Optionally a set of status meta registers can be loaded as well.
    /// The argument is a list of tuples with the following format:
    /// (regname, regidx, reg_shift_offset, reg_width, description)
    fn load_reg_metas(&mut self, reg_metas: Vec<MetaRegister>, stat_metas: Option<Vec<StatusMetaRegister>>) {
        let data = self.get_register_context_data_mut();
        data._rctx_reg_metas.clone_from(&reg_metas);
        for meta_register in reg_metas {
            let new_indx = (meta_register.shift_offset << 24) + (meta_register.size << 16) + meta_register.index;
            data._rctx_names.insert(meta_register.name.clone(), new_indx);
            data._rctx_ids.insert(new_indx, meta_register.name.clone());
        }
        data._rctx_stat_metas = stat_metas;
    }
    
    fn is_meta_register(&self, index: i32) -> bool {
        (index & 0xffff) != index
    }

    /// Return an object which can be stored off, and restored
    /// to re-initialize a register context.  (much like snapshot
    /// but it takes the definitions with it)
    fn get_register_info(&self, _meta: Option<bool>) -> (Vec<(String, i32)>, Vec<MetaRegister>, i32, i32, Vec<i32>){
        let data = self.get_register_context_data();
        let reg_def = data._rctx_reg_def.clone();
        let reg_metas = data._rctx_reg_metas.clone();
        let pc_index = data._rctx_pc_index;
        let sp_index = data._rctx_sp_index;
        let snap = self.get_register_snap();
        (reg_def, reg_metas, pc_index, sp_index, snap)
    }
    
    fn set_register_info(&mut self, reg_info: (Vec<(String, i32)>, Vec<MetaRegister>, i32, i32, Vec<i32>)){
        let (reg_def, reg_metas, pc_index, sp_index, snap) = reg_info;
        self.load_reg_def(reg_def, None);
        self.load_reg_metas(reg_metas, None);
        self.set_register_snap(snap);
        self.set_register_indexes(pc_index, sp_index, None);
    }
    
    fn get_register_name(&self, index: i32) -> String {
        let data = self.get_register_context_data();
        data._rctx_ids.get(&index).unwrap_or(&format!("REG{:0>8}", index)).clone()
    }

    /// Get the value of the program counter for this register context.
    fn get_program_counter(&self) -> i32 {
        self.get_register(self.get_register_context_data()._rctx_pc_index)
    }

    /// Set the value of the program counter for this register context.
    fn set_program_counter(&mut self, pc: i32) {
        self.set_register(self.get_register_context_data()._rctx_pc_index, pc);
    }
    
    fn get_stack_counter(&self) -> i32 {
        self.get_register(self.get_register_context_data()._rctx_sp_index)
    }
    
    fn set_stack_counter(&mut self, sp: i32) {
        self.set_register(self.get_register_context_data()._rctx_sp_index, sp);
    }

    /// Returns True if this context is aware of a status register.
    fn has_status_register(&self) -> bool {
        self.get_register_context_data()._rctx_sr_index.is_some()
    }
    
    /// Return a list of status register names and descriptions.
    fn get_status_reg_name_desc(&self) -> Vec<(String, String)> {
        let data = self.get_register_context_data();
        let mut ret = vec![];
        if let Some(stat_metas) = &data._rctx_stat_metas {
            for stat_meta in stat_metas {
                ret.push((stat_meta.name.clone(), stat_meta.description.clone()));
            }
        }
        ret
    }

    /// Gets the status register for this register context.
    fn get_status_register(&self) -> Option<i32> {
        if let Some(sr_index) = self.get_register_context_data()._rctx_sr_index {
            return Some(self.get_register(sr_index));
        }
        None
    }

    /// Sets the status register for this register context.
    fn set_status_register(&mut self, value: i32) {
        if let Some(sr_index) = self.get_register_context_data_mut()._rctx_sr_index {
            self.set_register(sr_index, value);
        }
    }

    /// Return a dictionary of reg name and reg value for the meta registers
    /// that are part of the status register.
    fn get_status_flags(&self) -> Result<HashMap<String, i32>> {
        let mut ret = HashMap::new();
        let data = self.get_register_context_data();
        if let Some(stat_metas) = &data._rctx_stat_metas {
            for stat_meta in stat_metas {
                let value = self.get_register_by_name(stat_meta.name.clone())?;
                ret.insert(stat_meta.name.clone(), value);
            }
        }
        Ok(ret)
    }

    fn get_register_by_name(&self, name: String) -> Result<i32> {
        let data = self.get_register_context_data();
        if let Some(index) = data._rctx_names.get(&name) {
            Ok(self.get_register(*index))
        } else {
            Err(InvalidRegisterName(name))
        }
    }

    fn set_register_by_name(&mut self, name: String, value: i32) -> Result<()> {
        let data = self.get_register_context_data();
        if let Some(index) = data._rctx_names.get(&name) {
            self.set_register(*index, value);
            Ok(())
        } else {
            Err(InvalidRegisterName(name))
        }
    }

    /// Returns a list of the 'real' (non meta) registers.
    fn get_register_names(&self) -> Vec<String> {
        let mut regs = vec![];
        let data = self.get_register_context_data();
        for (name, rindx) in &data._rctx_names {
            if !self.is_meta_register(*rindx) {
                regs.push(name.clone());
            }
        }
        regs
    }

    /// Return a list of all the 'real' (non meta) registers and their indexes.
    ///
    /// Example: for regname, regidx in x.getRegisterNameIndexes():
    fn get_register_name_indexes(&self) -> Vec<(String, i32)> {
        let mut ret = vec![];
        let data = self.get_register_context_data();
        for (rname, rindx) in data._rctx_names.clone() {
            if !self.is_meta_register(rindx) {
                ret.push((rname, rindx));
            }
        }
        ret
    }

    /// Get all the *real* registers from this context as a dictionary of name
    /// value pairs.
    fn get_registers(&self) -> HashMap<&str, i32> {
        let mut ret = HashMap::new();
        let data = self.get_register_context_data();
        for (name, rindx) in &data._rctx_names {
            if rindx & 0xffff != *rindx {
                continue;
            }
            ret.insert(name.as_str(), self.get_register(*rindx));
        }
        ret
    }

    /// For any name value pairs in the specified dictionary, set the current
    /// register values in this context.
    fn set_registers(&mut self, regs: HashMap<String, i32>) -> Result<()> {
        for (name, value) in regs {
            self.set_register_by_name(name, value)?;
        }
        Ok(())
    }

    /// Get a register index by name.
    /// (faster to use the index multiple times)
    fn get_register_index(&self, name: String) -> Result<i32> {
        let data = self.get_register_context_data();
        if let Some(index) = data._rctx_names.get(&name) {
            Ok(*index)
        } else {
            Err(InvalidRegisterName(name))
        }
    }

    /// Return the width of the register which lives at the specified
    /// index (width is always in bits).
    fn get_register_width(&self, index: i32) -> i32 {
        let data = self.get_register_context_data();
        let rindx = index & 0xffff;
        if rindx == index {
            return data._rctx_widths[index as usize];
        }
        (index >> 16) & 0xff
    }

    /// Return the current value of the specified register index.
    fn get_register(&self, index: i32) -> i32{
        let rindx = index & 0xffff;
        let data = self.get_register_context_data();
        let mut value = data._rctx_vals[rindx as usize];
        if rindx != index {
            value = self._xlate_to_meta_reg(index, value);
        }
        value
    }

    /// Return the appropriate realreg, shift, mask info
    /// for the specified metareg idx (or None if it's not
    /// meta).
    /// 
    /// Example:
    /// real_reg, lshift, mask = r.getMetaRegInfo(x)
    fn get_meta_reg_info(&self, index: i32) -> Option<(i32, i32, i32)> {
        let rindx = index & 0xffff;
        if rindx == index {
            return None;
        }
        let offset = (index >> 24) & 0xff;
        let width = (index >> 16) & 0xff;
        let mask = (2i32.pow(width as u32)) - 1;
        Some((rindx, offset, mask))
    }

    /// Translate a register value to the meta register value
    /// (used when getting a meta register)
    fn _xlate_to_meta_reg(&self, index: i32, mut value: i32) -> i32 {
        let offset = (index >> 24) & 0xff;
        let width = (index >>16) & 0xff;
        
        let mask = 2i32.pow(width as u32) - 1;
        if offset != 0 {
            value >>= offset;
        }
        value & mask
    }

    /// Translate a register value to the native register value
    /// (used when setting a meta register)
    fn _xlate_to_native_reg(&self, index: i32, mut value: i32) -> i32 {
        let rindx = index & 0xffff;
        let offset = (index >> 24) & 0xff;
        let width = (index >> 16) & 0xff;
        let mut mask = (2i32.pow(width as u32)) - 1;
        mask <<= offset;
        let data = self.get_register_context_data();
        let base_width = data._rctx_widths[rindx as usize];
        let base_mask = (2i32.pow(base_width as u32)) - 1;
        let final_mask = base_mask ^ mask;
        let curval = data._rctx_vals[rindx as usize];
        if offset != 0 {
            value <<= offset;
        }
        (value & mask) | (curval & final_mask)
    }
    
    /// Set a register value by index.
    fn set_register(&mut self, index: i32, mut value: i32) {
        let rindx = index & 0xffff;
        let data = self.get_register_context_data_mut();
        data._rctx_dirty = true;
        if rindx != index {
            value = {
                let rindx = index & 0xffff;
                let offset = (index >> 24) & 0xff;
                let width = (index >> 16) & 0xff;
                let mut mask = (2i32.pow(width as u32)) - 1;
                mask <<= offset;
                let base_width = data._rctx_widths[rindx as usize];
                let base_mask = (2i32.pow(base_width as u32)) - 1;
                let final_mask = base_mask ^ mask;
                let curval = data._rctx_vals[rindx as usize];
                if offset != 0 {
                    value <<= offset;
                }
                (value & mask) | (curval & final_mask)
            }
        }
        data._rctx_vals[rindx as usize] = value & data._rctx_masks[rindx as usize];
    }

    /// Returns the Name of the Containing register (in the case
    /// of meta-registers) or the name of the register.
    /// (by Index)
    fn get_real_register_name_by_index(&self, index: i32) -> String {
        self.get_register_name((index as i64 & RMETA_NMASK) as i32)
    }

    /// Returns the Name of the Containing register (in the case
    /// of meta-registers) or the name of the register.
    fn get_real_register_name(&self, name: String) -> String {
        if let Ok(index) = self.get_register_index(name.clone()) {
            return self.get_register_name(index)
        } 
        name
    }
}