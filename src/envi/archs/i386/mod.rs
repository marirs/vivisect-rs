pub mod registers;

use crate::envi::archs::i386::registers::I386RegisterContext;
use crate::envi::registers::RegisterContext;
use crate::envi::{ArchitectureModule, ArchitectureModuleData};
use std::rc::Rc;

#[derive(Clone, Default)]
pub struct I386Module {
    arch_data: ArchitectureModuleData,
}

impl I386Module {
    pub fn new() -> Self {
        I386Module::default()
    }
}

impl ArchitectureModule for I386Module {
    fn get_data_mut(&mut self) -> &mut ArchitectureModuleData {
        &mut self.arch_data
    }

    fn get_data(&self) -> &ArchitectureModuleData {
        &self.arch_data
    }

    fn arch_get_reg_ctx(&self) -> crate::envi::Result<Rc<dyn RegisterContext>> {
        let context = Rc::new(I386RegisterContext::new());
        let cast_context = context as Rc<dyn RegisterContext>;
        Ok(cast_context)
    }
}
