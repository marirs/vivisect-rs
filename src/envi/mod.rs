use crate::monitor::EmulationMonitor;

pub trait CallingConvention {
    fn get_num_stack_arguments(&self, emu: &EmulationMonitor, argc: i32) -> usize;
    
    fn get_call_args(&self, emu: &EmulationMonitor, argc: i32) -> Vec<u64>;
}