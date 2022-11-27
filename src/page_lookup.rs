#![allow(dead_code, unused)]
use std::collections::HashMap;
use log::{debug};

#[derive(Clone, Debug)]
pub struct MapLookUp {
    maps_list: Vec<(i32, i32, Vec<Option<(i32, i32, i32, Vec<(i32, i32)>)>>)>
}

impl MapLookUp {
    pub fn new() -> Self{
        MapLookUp{
            maps_list: Vec::new()
        }
    }
    
    pub fn init_map_lookup(&mut self, va: i32, size: i32, obj: Option<(i32, i32, i32, Vec<(i32, i32)>)>) {
        debug!("Initializing map lookup.. Size: {}", size);
        let marray = vec![obj; size as usize];
        self.maps_list.push((va, va+size, marray));
    }
    
    pub fn set_map_lookup(&self, va: i32, size: i32, obj: Option<(i32, i32, i32, Vec<(i32, i32)>)>) {
        for (mva, mvamax, mut marray) in self.maps_list.clone() {
            if va >= mva && va < mvamax {
                let off = va - mva;
                for i in off..off+size {
                    *marray.get_mut(i as usize).unwrap() = Some(obj.as_ref().cloned().unwrap().clone());
                }
                return;
            }
        }
        panic!("Address ({:#0x}) not in maps!", va);
    }
    
    pub fn get_map_lookup(&self, va: i32) -> Option<(i32, i32, i32, Vec<(i32, i32)>)> {
        // FIXME Needs some optimization.
        // for (mva, mva_max, m_array) in self.maps_list.clone() {
        for map in self.maps_list.clone() {
            if va >= map.0 && va < map.1 {
                return map.2.get((va - map.0) as usize).unwrap().clone();
            }
        } 
        None
    }
    
    pub fn del_map_lookup(&mut self, va: i32) -> (i32, i32, Vec<Option<(i32, i32, i32, Vec<(i32, i32)>)>>) {
        for midx in 0..self.maps_list.len() {
            let (mva, mvamax, marray) = self.maps_list.get(midx).unwrap();
            if va >= *mva && va < *mvamax {
                return self.maps_list.remove(midx);
            }
        }
        panic!("Map not found ({:#0x})", va);
    }
}

pub struct PageLookup {
    page_dict: HashMap<i32, Vec<i32>>
}

impl PageLookup {
    pub fn new() -> Self{
        PageLookup {
            page_dict: HashMap::new()
        }
    }
    
    pub fn get_page_lookup(&self, va: i32) -> Option<i32>{
        let page = self.page_dict.get(&(va >> 16));
        if page.is_none() {
            return None;
        }
        page.unwrap().get((va & 0xffff) as usize).map(|x| *x)
    }
}