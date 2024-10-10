mod registers;

use std::rc::Rc;
use crate::envi::{ArchitectureModule, ArchitectureModuleData};
use crate::envi::archs::i386::registers::I386RegisterContext;
use crate::envi::registers::RegisterContext;

pub struct I386Module{}

impl I386Module {
	pub fn new() -> Self {
		I386Module{}
	}
}

impl ArchitectureModule for I386Module {
	fn get_data_mut(&mut self) -> &mut dyn ArchitectureModuleData {
		unimplemented!()
	}

	fn get_data(&self) -> &dyn ArchitectureModuleData {
		unimplemented!()
	}

	fn arch_get_reg_ctx(&self) -> crate::envi::Result<Rc<dyn RegisterContext>> {
		let context = Rc::new(I386RegisterContext::new());
		let cast_context = context as Rc<dyn RegisterContext>;
		Ok(cast_context)
	}
}
