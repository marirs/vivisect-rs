#![allow(dead_code, unused)]

use crate::memory::Memory;

pub trait CodeFlowContext {}

pub struct VivCodeFlowContext {
    mem: Box<dyn Memory>,
}

impl VivCodeFlowContext {
    pub fn new(mem: Box<dyn Memory>, persist: bool, exp_table: bool, recurse: bool) -> Self {
        VivCodeFlowContext { mem }
    }

    pub fn _cb_no_flow(&mut self, srcva: i32, dstva: i32) {}
}

impl CodeFlowContext for VivCodeFlowContext {}
