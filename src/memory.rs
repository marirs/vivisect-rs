#![allow(dead_code, unused)]

use crate::{
    constants::{MM_EXEC, MM_READ, MM_SHARED, MM_WRITE},
    emulator::GenericEmulator,
    utils::parse_bytes,
};
use log::{debug, info, warn};
use std::{cmp::min, collections::HashMap};

pub trait Memory {
    /// Returns the Endianness setting
    fn get_endian(&mut self) -> i32;

    /// Set endianness for memory and architecture modules
    fn set_endian(&mut self, endianess: i32);

    fn set_mem_architecture(&mut self, arch: u32);

    /// Get a reference to the default arch module for the memory object.
    fn get_mem_architecture(&mut self) -> u32;

    fn read_memory(&self, va: i32, size: i32) -> Option<Vec<u8>>;

    fn write_memory(&mut self, va: i32, bytes: Vec<u8>);

    fn protect_memory(&mut self, va: i32, size: i32, perms: i32);

    /// Check to be sure that the given virtual address and size
    /// is contained within one memory map, and check that the
    /// perms are contained within the permission bits
    /// for the memory map. (MM_READ | MM_WRITE | MM_EXEC | ...)
    /// Example probeMemory(0x41414141, 20, envi.memory.MM_WRITE)
    /// (check if the memory for 20 bytes at 0x41414141 is writable)
    fn probe_memory(&mut self, va: i32, size: i32, perm: i32) -> bool {
        let mmap = self.get_memory_map(va);
        if mmap.is_none() {
            return false;
        }
        let (map_va, map_size, map_perm, map_file) = mmap.unwrap();
        let map_end = map_va + map_size;
        if (va + size) > map_end {
            return false;
        }
        if map_perm & perm != perm {
            return false;
        }
        true
    }

    fn allocate_memory(&mut self, size: i32, perms: i32, suggest_addr: i32);

    fn add_memory_map(
        &mut self,
        mapva: i32,
        perms: i32,
        fname: &str,
        bytes: Vec<u8>,
        align: Option<i32>,
    ) -> i32;

    fn get_memory_maps(&mut self) -> Vec<(i32, i32, i32, String)>;

    fn read_memory_format(&mut self, va: i32, fmt: &str);

    /// Read a number from memory of the given size.
    fn read_mem_value(&mut self, addr: i32, size: i32) -> Option<i32> {
        let bytes = self.read_memory(addr, size);
        if bytes.is_none() {
            return None;
        }
        if bytes.as_ref().cloned().unwrap().len() != size as usize {
            warn!(
                "Read gave wrong length a va: {:0x} (Wanted {} got {})",
                addr,
                size,
                bytes.as_ref().cloned().unwrap().len()
            );
            return None;
        }
        parse_bytes(bytes, 0, size, false, self.get_endian())
    }

    /// Write a number from memory of the given size.
    fn write_mem_value(&mut self, addr: i32, val: i32, size: i32) {
        let bytes = val.to_ne_bytes().to_vec()[..size as usize].to_vec();
        self.write_memory(addr, bytes);
    }

    fn get_memory_map(&mut self, va: i32) -> Option<(i32, i32, i32, String)> {
        for (mapva, size, perms, mname) in self.get_memory_maps() {
            if mapva <= va && va < (mapva + size) {
                return Some((mapva, size, perms, mname));
            }
        }
        None
    }

    fn is_executable(&mut self, va: i32) -> bool {
        let map_tup = self.get_memory_map(va);
        if map_tup.is_none() {
            return false;
        }
        (map_tup.unwrap().2 & MM_EXEC) == 1
    }

    fn is_readable(&mut self, va: i32) -> bool {
        let mat_up = self.get_memory_map(va);
        if mat_up.is_none() {
            return false;
        }
        (mat_up.unwrap().2 & MM_READ) == 1
    }

    fn is_writeable(&mut self, va: i32) -> bool {
        let mat_up = self.get_memory_map(va);
        if mat_up.is_none() {
            return false;
        }
        (mat_up.unwrap().2 & MM_WRITE) == 1
    }

    fn is_shared(&mut self, va: i32) -> bool {
        let mat_up = self.get_memory_map(va);
        if mat_up.is_none() {
            return false;
        }
        (mat_up.unwrap().2 & MM_SHARED) == 1
    }

    fn is_valid_pointer(&mut self, va: i32) -> bool {
        self.get_memory_map(va).is_some()
    }
}

pub trait MemoryCache {
    fn get_mem(&self) -> Box<dyn Memory>;

    fn get_page_size(&self) -> i32;

    fn get_page_mask(&self) -> i32;

    fn get_page_cache(&self) -> HashMap<i32, Vec<u8>>;

    fn get_page_dirty(&self) -> HashMap<i32, bool>;

    ///  Clear the "dirty cache" allowing tracking of writes *since* this call.
    fn clear_dirty_pages(&mut self) {
        self.get_page_dirty().clear();
    }

    fn is_dirty_page(&self, va: i32) {
        self.get_page_dirty()
            .get(&(va & self.get_page_mask()))
            .get_or_insert(&false);
    }

    /// Returns a list of dirty pages as (pageva, pagebytez) tuples.
    fn get_dirty_pages(&self) -> Vec<(i32, bool)> {
        self.get_page_dirty()
            .iter()
            .filter(|&x| *x.1)
            .map(|x| (*x.0, *x.1))
            .collect::<Vec<_>>()
    }
}

impl<T> Memory for T
where
    T: MemoryCache,
{
    fn get_endian(&mut self) -> i32 {
        todo!()
    }

    fn set_endian(&mut self, endian: i32) {
        todo!()
    }

    fn set_mem_architecture(&mut self, arch: u32) {
        todo!()
    }

    fn get_mem_architecture(&mut self) -> u32 {
        todo!()
    }

    fn read_memory(&self, mut va: i32, mut size: i32) -> Option<Vec<u8>> {
        let mut ret = Vec::new();
        while size > 0 {
            let page_va = va & self.get_page_mask();
            let page_off = va - page_va;
            let chunk_size = min(self.get_page_size() - page_off, size);
            let mut page = self.get_page_cache().get(&page_va).cloned();
            if page.is_none() {
                page = self.get_mem().read_memory(page_va, self.get_page_size());
                self.get_page_cache()
                    .insert(page_va, page.as_ref().cloned().unwrap());
            }
            ret.append(
                &mut page.as_ref().cloned().unwrap()
                    [page_off as usize..(page_off + chunk_size) as usize]
                    .to_vec(),
                // .iter()
                // .copied
                // .collect::<Vec<_>>(),
            );
            va += chunk_size;
            size -= chunk_size;
        }
        Some(ret)
    }

    fn write_memory(&mut self, mut va: i32, mut bytes: Vec<u8>) {
        while !bytes.is_empty() {
            let page_va = va & self.get_page_mask();
            let page_off = va - page_va;
            let chunk_size = min(self.get_page_size(), bytes.len() as i32);
            let mut page = self.get_page_cache().get(&page_va).cloned();
            if page.is_none() {
                page = self.get_mem().read_memory(page_va, self.get_page_size());
                self.get_page_cache()
                    .insert(page_va, page.as_ref().cloned().unwrap());
            }
            let mut new_bytes = Vec::new();
            new_bytes.append(
                &mut page.as_ref().cloned().unwrap()[..page_off as usize].to_vec(),
                // .iter()
                // .copied()
                // .collect::<Vec<_>>(),
            );
            new_bytes.append(
                &mut bytes[..chunk_size as usize].to_vec(),
                // .iter()
                // .copied()
                // .collect::<Vec<_>>(),
            );
            new_bytes.append(
                &mut page.unwrap()[(page_off + chunk_size) as usize..].to_vec(),
                // .iter()
                // .copied()
                // .collect::<Vec<_>>(),
            );
            *self.get_page_dirty().get_mut(&page_va).unwrap() = true;
            page = Some(new_bytes);
            self.get_page_cache().insert(page_va, page.unwrap());
            va += chunk_size;
            bytes = bytes[chunk_size as usize..].to_vec();
            // .iter()
            // .copied()
            // .collect::<Vec<_>>();
        }
    }

    fn protect_memory(&mut self, va: i32, size: i32, perms: i32) {
        todo!()
    }

    fn allocate_memory(&mut self, size: i32, perms: i32, suggest_addr: i32) {
        todo!()
    }

    fn add_memory_map(
        &mut self,
        mapva: i32,
        perms: i32,
        fname: &str,
        bytes: Vec<u8>,
        align: Option<i32>,
    ) -> i32 {
        todo!()
    }

    fn get_memory_maps(&mut self) -> Vec<(i32, i32, i32, String)> {
        todo!()
    }

    fn read_memory_format(&mut self, va: i32, fmt: &str) {
        todo!()
    }
}

impl MemoryCache for GenericEmulator {
    fn get_mem(&self) -> Box<dyn Memory> {
        todo!()
    }

    fn get_page_size(&self) -> i32 {
        todo!()
    }

    fn get_page_mask(&self) -> i32 {
        todo!()
    }

    fn get_page_cache(&self) -> HashMap<i32, Vec<u8>> {
        todo!()
    }

    fn get_page_dirty(&self) -> HashMap<i32, bool> {
        todo!()
    }
}
