use log::Level;
use simple_logger::init_with_level;
use std::env::current_dir;
use std::rc::Rc;
use vivisect::analysis::{EntryPointsAnalyzer, RelocationsAnalyzer};
use vivisect::workspace::VivWorkspace;

pub fn main() {
    init_with_level(Level::Trace).unwrap();
    println!("{:?}", current_dir());
    let sample_path = "data/test-decode-to-stack.exe";
    let mut workspace = VivWorkspace::new("", false);
    workspace.load_from_file(sample_path, None, None);
    workspace.add_analyzer(Rc::new(RelocationsAnalyzer::new()));
    workspace.add_analyzer(Rc::new(EntryPointsAnalyzer::new()));
    workspace.analyze(sample_path);
    // println!("{:?}", workspace);
}
