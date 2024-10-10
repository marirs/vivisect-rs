use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::Deref;
use std::rc::Rc;
use crate::envi::constants::{ARCH_DEFAULT, ARCH_MASK, MM_EXEC,Endianess, PAGE_MASK, MM_READ, MM_SHARED, MM_WRITE, PAGE_NMASK};
use crate::envi::ArchitectureModule;
use crate::error::Error::{MapNotFound, NoValidFreeMemoryFound, SegmentationViolation};
use crate::envi::operands::OpCode;
use crate::envi::Result;

pub type MemoryDef = (i32, i32, MemoryMap, Vec<u8>);

pub type MemoryMap = (i32, i32, i32, Option<String>);

pub trait MemoryData {
    fn get_imem_archs(&self) -> Vec<&Rc<dyn ArchitectureModule>>;

    fn get_imem_psize(&self) -> i32;
}

/// This is the interface spec (and a few helper utils)
/// for the unified memory object interface.
///
/// NOTE: If your actual underlying memory format is such
/// that over-riding anything (like isValidPointer!) can
/// be faster than the default implementation, DO IT!
pub trait Memory {
    fn get_memory_data(&self) -> &Rc<dyn MemoryData>;

    fn get_endian(&self) -> Endianess;

    fn set_endian(&mut self, endian: Endianess);

    fn set_mem_architecture(&mut self, arch: i32);

    /// Get a reference to the default arch module for the memory object.
    fn get_mem_arch_module(&self, arch: Option<i32>) -> &Rc<dyn ArchitectureModule> {
        let arch = arch.unwrap_or(ARCH_DEFAULT);
        self.get_memory_data().get_imem_archs()[arch as usize]
    }

    fn get_pointer_size(&self) -> i32;

    /// Read memory from the specified virtual address for size bytes
    /// and return it as a rust String.
    ///
    /// Example: mem.read_memory(0x41414141, 20) -> "A..."
    fn read_memory(&self, addr: i32, size: i32) -> Option<Vec<u8>>;

    /// Write the given bytes to the specified virtual address.
    ///
    /// Example: mem.write_memory(0x41414141, "VISI".as_bytes())
    fn write_memory(&self, addr: i32, data: &[u8]);

    /// Change the protections for the given memory map. On most platforms
    /// the va/size *must* exactly match an existing memory map.
    fn protect_memory(&self, addr: i32, size: i32, perms: i32);

    /// Check to be sure that the given virtual address and size
    /// is contained within one memory map, and check that the
    /// perms are contained within the permission bits
    /// for the memory map. `(MM_READ | MM_WRITE | MM_EXEC | ...)`
    ///
    /// Example:
    /// ```ignore
    /// mem.probe_memory(0x41414141, 20, MM_WRITE) //check if the memory for 20 bytes at 0x41414141 is writable
    /// ```
    fn probe_memory(&self, va: i32, size: i32, perm: i32) -> bool {
        let mmap = self.get_memory_map(va);
        if mmap.as_ref().is_none() {
            return false;
        }
        let (map_va, map_size, map_perms, _) = mmap.unwrap();
        let map_end = map_va + map_size;
        if va + size > map_end {
            return false;
        }
        if (perm & map_perms) != perm {
            return false;
        }
        true
    }

    fn allocate_memory(&self, size: i32, perms: i32, suggest_addr: Option<i32>);

    fn add_memory_map(&self, map_va: i32, perms: i32, f_name: &str, data: Option<&[u8]>, align: Option<i32>);

    fn get_memory_maps(&self) -> Vec<(i32, i32, i32, Option<String>)>;

    fn read_memory_format(&self, _addr: i32, _fmt: &str) -> Vec<i32> {
        unimplemented!()
    }

    fn write_memory_format(&self, addr: i32, mut fmt: String, data: &[i32]) {
        let memory_data = self.get_memory_data();
        if memory_data.get_imem_psize() == 4 {
            fmt = fmt.replace("P", "I");
        } else if memory_data.get_imem_psize() == 8 {
            fmt = fmt.replace("P", "Q");
        }
        // Pack the data and fmt into a struct and write it to memory
        let packed_data = format!("{{\"fmt\": {fmt}, \"data\": {data:?} }}");
        self.write_memory(addr, packed_data.as_bytes());
    }

    fn get_segment_info(&self, _va: i32) -> (i32, i64) {
        (0, 0xffffffff)
    }

    /// Read a number from memory of the given size.
    fn read_mem_value(&self, addr: i32, size: i32) -> Option<i64> {
        let bytes = self.read_memory(addr, size);
        None
    }

    /// Write a number from memory of the given size.
    fn write_mem_value(&self, addr: i32, value: i64, size: i32) {
        let mut bytes = vec![0; size as usize];
        for i in 0..size {
            bytes[i as usize] = (value >> (i * 8)) as u8;
        }
        self.write_memory(addr, &bytes);
    }

    /// Return a tuple of mapva,size,perms,filename for the memory
    /// map which contains the specified address (or None).
    fn get_memory_map(&self, va: i32) -> Option<(i32, i32, i32, Option<String>)> {
        for (map_va, size, perms, m_name) in self.get_memory_maps() {
            if map_va <= va && va < (map_va + size) {
                return Some((map_va, size, perms, m_name));
            }
        }
        None
    }

    fn is_valid_pointer(&self, va: i32) -> bool {
        self.get_memory_map(va).is_some()
    }

    /// Return the number of contiguous bytes that can be read from the
    /// specified va.
    fn get_max_read_size(&self, va: i32) -> i32 {
        let mut n_read= 0;
        let mut mmap = self.get_memory_map(va);
        while mmap.as_ref().is_some() {
            let (map_va, size, perms, _m_name) = mmap.unwrap();
            if (perms & MM_READ) == 0 {
                break;
            }
            n_read += (map_va + size) - (va - n_read);
            mmap = self.get_memory_map(va + n_read);
        }
        n_read
    }

    fn is_readable(&self, va: i32) -> bool {
        let mmap = self.get_memory_map(va);
        if mmap.as_ref().is_none() {
            return false;
        }
        let (_, _, perms, _) = mmap.unwrap();
        (perms & MM_READ) != 0
    }

    fn is_writable(&self, va: i32) -> bool {
        let mmap = self.get_memory_map(va);
        if mmap.as_ref().is_none() {
            return false;
        }
        let (_, _, perms, _) = mmap.unwrap();
        (perms & MM_WRITE) != 0
    }

    fn is_executable(&self, va: i32) -> bool {
        let mmap = self.get_memory_map(va);
        if mmap.as_ref().is_none() {
            return false;
        }
        let (_, _, perms, _) = mmap.unwrap();
        (perms & MM_EXEC) != 0
    }

    fn is_shared(&self, va: i32) -> bool {
        let mmap = self.get_memory_map(va);
        if mmap.as_ref().is_none() {
            return false;
        }
        let (_, _, perms, _) = mmap.unwrap();
        (perms & MM_SHARED) != 0
    }

    fn parse_op_code(&self, va: Option<i32>, arch: Option<i32>) -> Result<OpCode> {
        let arch = arch.unwrap_or(ARCH_DEFAULT);
        let b = self.read_memory(va.unwrap(), 16).unwrap();
        self.get_memory_data().get_imem_archs()[arch as usize >> 16].arch_parse_opcode(b, Some(0), va)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemoryObjectData {
    pub map_defs: Vec<MemoryDef>,
    pub supervisor: bool
}


pub trait MemoryObject: Memory + Debug {
    fn get_memory_object_data_mut(&mut self) -> &mut MemoryObjectData;

    fn get_memory_object_data(&self) -> &MemoryObjectData;

    /// Find a free block of memory (no maps exist) and allocate a new map
    /// Uses findFreeMemoryBlock()
    fn allocate_memory(&mut self,
                       size: i32,
                       perms: i32,
                       suggest_addr: Option<i32>,
                       name: Option<String>,
                       fill: Option<u8>,
                       align: Option<i32>
    ) -> Result<i32> {
        let base_va = self.find_free_memory_block(size, suggest_addr, None)?;
        let name = name.unwrap_or_default();
        let data = vec![fill.unwrap_or(0x00); size as usize];
        MemoryObject::add_memory_map(self, base_va, perms, name.as_str(), data.as_slice(), align);
        Ok(base_va)
    }

    /// Find a block of memory in the address-space of the correct size which
    /// doesn't overlap any existing maps.  Attempts to offer the map starting
    /// at suggestaddr.  If not possible, scans the rest of the address-space
    /// until it finds a suitable location or loops twice(ie. no gap large
    /// enough to accommodate a map of this size exists.
    ///
    /// DOES NOT ALLOCATE.  see allocateMemory() if you want the map created
    fn find_free_memory_block(&self, size: i32, suggest_addr: Option<i32>, min_mem_addr: Option<i32>) -> Result<i32> {
        let data = self.get_memory_data();
        let mut base_va = None;
        let mut looped = false;

        let mut temp_va = suggest_addr.unwrap_or(0x1000);
        let max_addr = (1 << (8 * data.get_imem_psize())) - 1;
        while base_va.is_none() {
            if temp_va > max_addr {
                if looped {
                    return Err(NoValidFreeMemoryFound(size))
                }
                looped = true;
                temp_va = min_mem_addr.unwrap_or(0x1000);
            }
            let mut good = true;
            let temp_end_va = temp_va + size - 1;
            for (mmva, mmsz, _, _) in MemoryObject::get_memory_maps(self) {
                let mmendva = mmva + mmsz - 1;
                if (temp_va <= mmva && mmva < temp_end_va) ||
                    (temp_va <= mmendva && mmendva < temp_end_va ) ||
                    (mmva <= temp_va && temp_va <= mmendva) ||
                    (mmva <= temp_end_va && temp_end_va <= mmendva) {
                    // we ran into a memory map.  adjust.
                    good = false;
                    temp_va = mmendva;
                    temp_va += PAGE_NMASK;
                    temp_va &= PAGE_MASK;
                    break;
                }
            }
            if good {
                base_va = Some(temp_va);
            }
        }
        Ok(base_va.unwrap())
    }

    /// Add a memory map to this object...
    /// Returns the length of the map (since alignment could alter it)
    fn add_memory_map(&mut self, map_va: i32, perms: i32, f_name: &str, data: &[u8], align: Option<i32>) -> i32 {
        let memory_data = self.get_memory_object_data_mut();
        let mut data_bytes = data.to_vec();
        if let Some(align) = align {
            let cur_len = data_bytes.len() as i32;
            let new_len = crate::envi::utils::align(cur_len, align);
            let delta = new_len - cur_len;
            data_bytes.append(&mut vec![0; delta as usize]);
        }
        let m_size = data_bytes.len() as i32;
        let m_map = (map_va, m_size, perms, Some(f_name.to_string()));
        let map_def = (map_va, map_va + m_size, m_map, data_bytes);
        memory_data.map_defs.push(map_def);
        m_size
    }

    /// Delete a memory map from this object...
    fn del_memory_map(&mut self, va: i32) -> Result<()> {
        let memory_data = self.get_memory_object_data_mut();
        for (indx, (map_va, _map_end, _, _)) in memory_data.map_defs.iter().enumerate() {
            if *map_va == va  {
                memory_data.map_defs.remove(indx);
                return Ok(());
            }
        }
        Err(MapNotFound(va))
    }

    /// Take a memory snapshot which may be restored later.
    ///
    /// Example: snap = mem.getMemorySnap()
    fn get_memory_snap(&self) -> Vec<MemoryDef> {
        let memory_data = self.get_memory_object_data();
        let mut mem = vec![];
        for mdef in memory_data.map_defs.iter() {
            mem.push(mdef.clone());
        }
        mem
    }

    /// Restore a previously saved memory snapshot.
    ///
    /// Example: mem.setMemorySnap(snap)
    fn set_memory_snap(&mut self, snap: Vec<MemoryDef>) {
        let memory_data = self.get_memory_object_data_mut();
        memory_data.map_defs = snap;
    }

    /// Get the va,size,perms,fname tuple for this memory map
    fn get_memory_map(&self, va: i32) -> Option<MemoryMap> {
        for (map_va, map_end, m_map, _) in self.get_memory_object_data().map_defs.iter() {
            if *map_va <= va && va < *map_end {
                return Some(m_map.clone());
            }
        }
        None
    }

    fn get_memory_maps(&self) -> Vec<MemoryMap> {
        self.get_memory_object_data().map_defs.iter().map(|(_, _, m_map, _)| m_map.clone()).collect()
    }

    /// Read memory from maps stored in memory maps.
    ///
    /// If the read crosses memory maps and fails on a later map, the Err
    /// will show the details of the last map/failure, but should include the
    /// original va (not the size).
    ///
    /// orig_va is an internal field and should not be used.
    fn read_memory(&self, va: i32, size: i32, mut orig_va: Option<i32>) -> Result<Vec<u8>> {
        let memory_data = self.get_memory_object_data();
        for (map_va, mmax_va, mmap, mbytes) in memory_data.map_defs.iter() {
            if *map_va <= va && va < *mmax_va {
                let (mva, msize, mperms, _mfname) = mmap;
                if (mperms & MM_READ) == 0 {
                    let mut msg = format!("Bad Memory Read (no READ permission): {:#0x}, {:#0x} ", va, size);
                    if let Some(orig_va) = orig_va {
                        msg.push_str(&format!("(original va: {:#0x})", orig_va));
                    }
                    return Err(SegmentationViolation(va, msg));
                }
                let offset = va - mva;
                let max_read_len = msize - offset;
                if size > max_read_len {
                    // if we're reading past the end of this map, recurse to find the next map
                    // perms checks for that map will be performed, and size, etc... and if
                    // an exception must be thrown, future readMemory() can throw it
                    if orig_va.is_none() {
                       orig_va = Some(va);
                    }
                    let mut data = mbytes[offset as usize..].to_vec();
                    data.append(&mut MemoryObject::read_memory(self, mva + msize, size - max_read_len, orig_va)?);
                    return Ok(data)
                }
                return Ok(mbytes[offset as usize..(offset + size) as usize].to_vec());
            }
        }
        let mut msg = format!("Bad Memory Read (Invalid memory address): {:#0x}, {:#0x} ", va, size);
        if let Some(orig_va) = orig_va {
            msg.push_str(&format!("(original va: {:#0x})", orig_va));
        }
        Err(SegmentationViolation(va, msg))
    }

    /// Write memory to maps stored in memory maps.
    ///
    /// If the write crosses memory maps and fails on a later map, the exception
    /// will show the details of the last map/failure, but should include the
    /// original va (but not the original size).
    /// In this scenario, writes to the first map will succeed, up until the address of the exception.
    ///
    /// orig_va is an internal field and should not be used.
    fn write_memory(&mut self, va: i32, data: &[u8], mut orig_va: Option<i32>) -> Result<()> {
        let memory_data = self.get_memory_object_data_mut();
        let bytes_len = data.len() as i32;
        for map_def in memory_data.map_defs.iter_mut() {
            let (map_va, mmax_va, mmap, mbytes) = map_def;
            if *map_va <= va && va < *mmax_va {
                let (mva, msize, mperms, _mfname) = mmap;
                if (*mperms & MM_WRITE) == 0 || memory_data.supervisor {
                    let mut msg = format!("Bad Memory Write (no WRITE permission): {:#0x}, {:#0x} ", va, bytes_len);
                    if let Some(orig_va) = orig_va {
                        msg.push_str(&format!("(original va: {:#0x})", orig_va));
                    }
                    return Err(SegmentationViolation(va, msg));
                }
                let offset = va - *mva;
                let max_write_len = *msize - offset;
                if bytes_len > max_write_len {
                    // if we're writing past the end of this map, recurse to find the next map
                    // perms checks for that map will be performed, and size, etc... and if
                    // an exception must be thrown, future writeMemory() can throw it
                    if orig_va.is_none() {
                        orig_va = Some(va);
                    }
                    let mut byte_data = mbytes[..offset  as usize].to_vec();
                    byte_data.append(&mut data[..max_write_len as usize].to_vec());
                    map_def.3 = byte_data;
                    // TODO: Fix this borrow multiple mutable self issue
                    //MemoryObject::write_memory(self, *mva + *msize, data[max_write_len as usize..].as_ref(), orig_va)?;
                } else {
                    let mut mbytes = mbytes[..offset as usize].to_vec();
                    mbytes.append(&mut data.to_vec());
                    mbytes.append(&mut mbytes[(offset + bytes_len) as usize..].to_vec());
                    map_def.3 = mbytes;
                }
                return Ok(())
            }
        }
        let mut msg = format!("Bad Memory Write (Invalid memory address): {:#0x}, {:#0x} ", va, bytes_len);
        if let Some(orig_va) = orig_va {
            msg.push_str(&format!("(original va: {:#0x})", orig_va));
        }
        Err(SegmentationViolation(va, msg))
    }

    /// An optimized routine which returns the existing
    /// segment bytes sequence without creating a new
    /// string object *AND* an offset of va into the
    /// buffer.  Used internally for optimized memory
    /// handling.  Returns (offset, bytes)
    fn get_byte_def(&self, va: i32) -> Result<(i32, Vec<u8>)> {
        let memory_data = self.get_memory_object_data();
        for (map_va, mmax_va, _, mbytes) in memory_data.map_defs.iter() {
            if *map_va <= va && va < *mmax_va {
                let offset = va - map_va;
                return Ok((offset, mbytes.clone()));
            }
        }
        Err(SegmentationViolation(va, "Invalid memory address".to_string()))
    }

    /// Parse an opcode from the specified virtual address.
    ///
    /// Example: op = m.parseOpcode(0x7c773803)
    fn parse_op_code(&self, va: i32, arch: Option<i32>) -> Result<OpCode> {
        let arch = arch.unwrap_or(ARCH_DEFAULT);
        let (offset, bytes) = self.get_byte_def(va)?;
        let data = self.get_memory_data();
        data.get_imem_archs()[((arch as i64 & ARCH_MASK) >> 16) as usize].arch_parse_opcode(bytes, Some(offset), Some(va))
    }

    /// Returns a C-style string from memory.  Stops at Memory Map boundaries, or the first NULL (\x00) byte.
    fn read_mem_string(&self, va: i32, max_len: Option<i32>) -> Result<Vec<u8>> {
        let max_len = max_len.unwrap_or(0xfffffff);
        for (mva, mmaxva, mmap, mbytes) in self.get_memory_object_data().map_defs.iter() {
            if *mva <= va && va < *mmaxva {
                let (mva, _msize, mperms, _mfname) = mmap;
                if (*mperms & MM_READ) == 0 {
                    return Err(SegmentationViolation(va, "Bad Memory Read (no READ permission)".to_string()));
                }
                let offset = va - mva;
                
                // now find the end of the string based on either \x00, maxlen, or end of map
                let mend = if let Some(end) = mbytes.iter().position(|&x| x == 0x00) {
                    // Couldn't find the NULL byte go to th eend of the map or maxlen
                    let left = end as i32 - offset;
                    if left < max_len {
                        offset + left
                    } else {
                        offset + max_len
                    }

                } else {
                    offset + max_len
                };
                let c_str = mbytes[offset as usize..mend as usize].to_vec();
                return Ok(c_str)
            }
        }
        Err(SegmentationViolation(va, "Invalid memory address".to_string()))
    }
}

#[derive(Clone, Debug)]
pub struct MemoryFile {
    base_addr: i32,
    offset: i32,
    mem_obj: Rc<dyn MemoryObject>
}

impl MemoryFile {
    pub fn new(mem_obj: Rc<dyn MemoryObject>, base_addr: i32) -> Self {
        MemoryFile {
            base_addr,
            offset: base_addr,
            mem_obj
        }
    }

    pub fn seek(&mut self, offset: i32) {
        self.offset = self.base_addr + offset;
    }

    pub fn read(&mut self, size: i32) -> Result<Vec<u8>> {
        let data = MemoryObject::read_memory(self.mem_obj.deref(), self.offset, size, None)?;
        self.offset += size;
        Ok(data)
    }

    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        MemoryObject::write_memory(Rc::get_mut(&mut self.mem_obj).unwrap(), self.offset, data, None)?;
        self.offset += data.len() as i32;
        Ok(())
    }
}

pub struct MemoryCache {
    memory: Rc<dyn Memory>,
    page_size: i32,
    page_mask: i32,
    page_cache: HashMap<i32, Vec<u8>>,
    page_dirty: HashMap<i32, bool>
}

impl MemoryCache {
    pub fn new(memory: Rc<dyn Memory>, page_size: Option<i32>) -> Self {
        let page_size = page_size.unwrap_or(4096);
        MemoryCache {
            memory,
            page_size,
            page_mask: !(page_size - 1),
            page_cache: HashMap::new(),
            page_dirty: HashMap::new()
        }
    }

    pub fn cache_page(&self, va: i32) -> Option<Vec<u8>> {
        self.memory.read_memory(va, self.page_size)
    }


    pub fn read_memory(&mut self, mut va: i32, mut size: i32) -> Result<Vec<u8>> {
        let mut data = vec![];
        while size != 0 {
            let page_va = va & self.page_mask;
            let page_offset = va - page_va;
            let chunk_size = std::cmp::min(size, self.page_size - page_offset);
            let mut page = self.page_cache.get(&page_va).cloned();
            if page.as_ref().is_none() {
                page = self.memory.read_memory(page_va, self.page_size);
                self.page_cache.insert(page_va, page.clone().unwrap());
            }
            data.append(&mut page.unwrap()[page_offset as usize..(page_offset + chunk_size) as usize].to_vec());
            va += chunk_size;
            size -= chunk_size;
        }
        Ok(data)
    }

    pub fn write_memory(&mut self, mut va: i32, mut data: &[u8]) {
        while data.len() != 0 {
            let page_va = va & self.page_mask;
            let page_offset = va - page_va;
            let chunk_size = std::cmp::min(data.len() as i32, self.page_size);
            let mut page = self.page_cache.get(&page_va).cloned();
            if page.as_ref().is_none() {
                page = self.memory.read_memory(page_va, self.page_size);
                self.page_cache.insert(page_va, page.clone().unwrap());
            }
            self.page_dirty.insert(page_va, true);
            let mut page_data = page.as_ref().unwrap()[..page_offset as usize].to_vec();
            page_data.append(&mut data[..chunk_size as usize].to_vec());
            page_data.append(&mut page.as_ref().unwrap()[(page_offset + chunk_size) as usize..].to_vec());
            page = Some(page_data);
            self.page_cache.insert(page_va, page.clone().unwrap());

            va += chunk_size;
            data = &data[chunk_size as usize..];
        }
    }
    
    pub fn clear_dirty_pages(&mut self) {
        self.page_dirty.clear()
    }
    
    pub fn is_dirty_page(&self, va: i32) -> bool {
        self.page_dirty
            .get(&(va & self.page_mask))
            .cloned()
            .unwrap_or(false)
    }
    
    /// Returns a list of dirty pages as (pageva, pagebytez) tuples.
    pub fn get_dirty_pages(&self) -> Vec<(i32, Vec<u8>)> {
        self.page_dirty
            .iter()
            .map(|(&k, _)| (k, self.page_cache.get(&k).cloned().unwrap()))
            .collect::<Vec<_>>()
    }
}
