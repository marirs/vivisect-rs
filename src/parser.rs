#![allow(dead_code, unused)]

use crate::constants::ARCH_DEFAULT;
use crate::ihex::IHexFile;
use crate::memory::Memory;
use crate::workspace::VivWorkspace;
use log::{debug, error, info};
use std::fs;
use std::io::{Cursor, Read};

pub fn parse_file(mut workspace: VivWorkspace, filename: &str, _base_addr: Option<i32>) -> String {
    workspace.set_meta("Architecture", Some(ARCH_DEFAULT.to_string()));
    workspace.set_meta("Platform", Some("Unknown".to_string()));
    workspace.set_meta("Format", Some("ihex".to_string()));
    let offset = 0;
    let ihex = IHexFile::new();
    let contents = fs::read(filename).expect("Error reading the file.");
    let mut cursor = Cursor::new(contents);
    let mut shdr = Vec::with_capacity(offset);
    cursor.read(&mut shdr).unwrap();
    let mut sbytes = Vec::new();
    cursor.read_to_end(&mut sbytes).unwrap();
    let fname: String = workspace.add_file(filename, 0, sbytes.clone());
    ihex.vs_parse(sbytes.clone(), 0);
    for eva in ihex.get_entry_points() {
        if eva.is_some() {
            info!(
                "Adding function from IHEX metadata: {:#0x}",
                eva.as_ref().cloned().unwrap()
            );
            workspace.add_entry_point(eva.as_ref().cloned().unwrap() as i32);
        }
    }
    let memory_maps = ihex.get_memory_maps();
    for (addr, perms, _, bytes) in memory_maps {
        workspace.add_memory_map(addr, perms, fname.as_str(), bytes.clone(), None);
        workspace.add_segment(
            addr,
            bytes.len() as i32,
            format!("{:#0x}", addr).as_str(),
            fname.clone(),
        );
    }
    fname
}
