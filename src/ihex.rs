#![allow(dead_code, unused)]

use crate::vstruct::VStruct;

pub const IHEX_REC_DATA : i32 = 0;
pub const IHEX_REC_EOF : i32 = 1;
pub const IHEX_REC_EXSEG : i32 = 2; // Extended Segment Address Records
pub const IHEX_REC_STARTSEG : i32 = 3; // The beginning code segment value
pub const IHEX_REC_EXLINADDR :i32 = 4; // Extended Linear Address Records
pub const IHEX_REC_STARTLINADDR : i32 = 5;

#[derive(Clone, Debug)]
pub struct IHexChunk {
    start_code: i32, 
    byte_count: i32,
    address: i32,
    record_type: i32,
    data: [u8; 2],
    csum: i32,
    vs_fields: Vec<i32>
}

impl IHexChunk {
    pub fn new() -> Self {
        IHexChunk {
            start_code: 0,
            byte_count: 0,
            address: 0,
            record_type: 0,
            data: [0; 2],
            csum: 0,
            vs_fields: Vec::new()
        }
    }
    
    pub fn pcb_byte_count(&self){
        
    }
    
    pub fn get_address(&self) -> i32{
        0
    }
    
    pub fn get_data(&self) -> [u8; 2] {
        self.data
    }
    
    pub fn len(&self) -> i32 {
        self.data.len() as i32
    }
}

impl VStruct for IHexChunk {
    fn get_vs_fields(&self) -> Vec<i32>{
        self.vs_fields.clone()
    }
}

#[derive(Clone, Debug)]
pub struct IHexFile{
    meta: Vec<(String, IHexChunk)>
}

impl IHexFile{
    pub fn new() -> Self {
        IHexFile{
            meta: Vec::new()
        }
    }
    
    pub fn vs_parse(&self, bytes: Vec<u8>, mut offset: i32) -> i32 {
        let mut lines = bytes[offset as usize..].split_inclusive(|x| char::from(*x) == '\n');
        for line in lines {
            offset += 1;
            if line.len() == 0{
                continue;
            }
            let c = IHexChunk::new();
            c.vs_parse(line.to_vec(), 0, false);
            offset += c.len();
            // self.add_element(c);
            if c.record_type == IHEX_REC_EOF {
                break;
            }
        }
        offset
    }
    
    pub fn get_entry_points(&self) -> Vec<Option<i32>>{
        let mut evas = Vec::new();
        for (fname, chunk) in self.meta.clone() {
            let c_type = chunk.record_type;
            if c_type == IHEX_REC_STARTLINADDR {
                evas.push(Some(i16::from_ne_bytes(chunk.data) as i32));
            } else if c_type == IHEX_REC_STARTSEG {
                let start_cs = i16::from_ne_bytes(chunk.data) as i32 >> 16 ;
                let  start_tip = i16::from_ne_bytes(chunk.data) as i32 & 0xff;
                evas.push(Some((start_cs << 4) | start_tip));
            }
        }
        evas
    }

    /// Retrieve a set of memory maps defined by this hex file.
    /// Memory maps are returned as a list of
    /// ( va, perms, fname, bytes ) tuples.
    pub fn get_memory_maps(&self) -> Vec<(i32, i32, String, &mut Vec<u8>)> {
        let mut base_addr: i32 = 0;
        let mut mem_parts: Vec<(i32, Vec<u8>)> = Vec::new();
        for (fname, chunk) in self.meta.clone() {
            let c_type = chunk.record_type;
            if c_type == IHEX_REC_DATA {
                let addr = chunk.get_address() + base_addr as i32;
                mem_parts.push((addr, chunk.get_data().to_vec()));
                continue;
            }
            if c_type == IHEX_REC_EXSEG {
                base_addr = (i16::from_ne_bytes(chunk.data) << 4) as i32;
                continue;
            }
            if c_type == IHEX_REC_EXLINADDR {
                base_addr = (i16::from_ne_bytes(chunk.data) as i32) << 16;
                continue;
            }
            if c_type == IHEX_REC_STARTSEG {
                continue;
            }
            if c_type == IHEX_REC_EOF {
                break;
            }
        }
        mem_parts.sort();
        let mut maps: Vec<(i32, i32, String, &mut Vec<u8>)> = Vec::new();
        for (addr, mut bytes) in mem_parts.clone(){
            if addr == (mem_parts.clone().last().unwrap().0 + maps.last().unwrap().3.len() as i32) {
                let last_el = maps.last().unwrap();
                last_el.3.to_vec().append(&mut bytes.to_vec());
            }
        }
        maps
    }
}

