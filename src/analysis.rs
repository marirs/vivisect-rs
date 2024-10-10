#![allow(dead_code, unused)]

use crate::{
    constants::{
        ARCH_DEFAULT, ARCH_MASK, BR_DEREF, BR_PROC, IF_NOFALL, LOC_OP, LOC_POINTER, LOC_STRING,
        LOC_UNI, L_LTYPE, REF_CODE, RTYPE_BASEOFF, RTYPE_BASERELOC,
    },
    emulator::OpCode,
    workspace::VivWorkspace,
};
use log::debug;
use std::{
    collections::HashMap,
    fmt::{Debug, Formatter},
    rc::Rc,
};

pub fn analyze_function(mut workspace: VivWorkspace, funcva: i32) {
    let mut blocks = Vec::new();
    let mut done: HashMap<i32, bool> = HashMap::new();
    let mut mnem: HashMap<String, i32> = HashMap::new();
    let mut todo = vec![funcva];
    let mut brefs = Vec::new();
    let mut size = 0;
    let mut opcount = 0;
    while let Some(start) = todo.pop() {
        // If we hit code we've already done, proceed.
        if *done.get(&start).unwrap() {
            continue;
        }
        *done.get_mut(&start).unwrap() = true;
        *blocks.get_mut(start as usize).unwrap() = 0;
        brefs.push((start, true));
        let mut va = start;
        let mut op: Option<OpCode> = None;
        // Set the default architecture.
        let mut arch = ARCH_DEFAULT;
        loop {
            let mut loc = workspace.get_location(va);
            if loc.is_none() {
                *blocks.get_mut(start as usize).unwrap() = va - start;
                brefs.push((va, false));
                break;
            }
            let (lva, lsize, ltype, linfo) = loc.unwrap();
            if ltype == LOC_POINTER {
                workspace.del_location(lva);
                // pointer analysis mis-identified a pointer,
                // so clear and re-analyze instructions.
                if op.is_some() {
                    arch = op.as_ref().cloned().unwrap().iflags & ARCH_MASK;
                }
                workspace.make_code(va, arch, funcva);
                loc = workspace.get_location(va);
                if loc.is_none() {
                    *blocks.get_mut(start as usize).unwrap() = va - start;
                    brefs.push((va, false));
                    break;
                }
                let (lva, lsize, ltype, linfo) = loc.unwrap();
            }
            if ltype != LOC_OP {
                *blocks.get_mut(start as usize).unwrap() = va - start;
                brefs.push((va, false));
                break;
            }

            op = workspace.parse_op_code(va);
            *mnem.get_mut(&op.as_ref().cloned().unwrap().mnem).unwrap() += 1;
            size += lsize;
            opcount += 1;
            let nextva = va + lsize;
            // For each of our code xrefs, create a new target.
            let mut branch = false;
            let xrefs = workspace.get_xrefs_from(va, Some(REF_CODE));
            for (from_va, to_va, r_type, r_flags) in xrefs {
                // We do not handle procedural branches here..
                if r_flags & BR_PROC == 1 {
                    continue;
                }
                // For now we'll skip jmp [import] thunks.
                if r_flags & BR_DEREF == 1 {
                    continue;
                }
                branch = true;
                todo.push(to_va);
                // If it doesn't fall through, terminate (at nextva)
                if (linfo.clone().first().unwrap().0 as u32 & IF_NOFALL) == 1 {
                    *blocks.get_mut(start as usize).unwrap() = nextva - start;
                    brefs.push((nextva, false));
                    break;
                }
                // If we hit a branch, we are at the end of the block.
                if branch {
                    *blocks.get_mut(start as usize).unwrap() = nextva - start;
                    todo.push(nextva);
                    break;
                }
                if !workspace.get_xrefs_to(nextva, Some(REF_CODE)).is_empty() {
                    *blocks.get_mut(start as usize).unwrap() = nextva - start;
                    todo.push(nextva);
                    break;
                }
                va = nextva;
            }
        }
    }
    let funcs = workspace.get_function_blocks(funcva);

    let mut old_blocks = HashMap::new();
    for (va, size, fva, _) in funcs.iter() {
        old_blocks.insert(va, size);
    }
    // We now have an ordered list of block references
    brefs.sort();
    brefs.reverse();
    let mut bcnt = 0;
    while let Some((bva, is_begin)) = brefs.pop() {
        if !is_begin {
            continue;
        }
        if brefs.is_empty() {
            break;
        }
        // So we don't add a code block if we're reanalyzing a function. (like dynamic branch analysis).
        let bsize = blocks.get(bva as usize).unwrap();
        let tmpcb = workspace.get_code_block(bva);
        // Sometimes codeblocks can be deleted if owned by multiple functions.
        if !old_blocks.contains_key(&bva) || tmpcb.is_none() {
            workspace.add_code_block(bva, bsize, funcva);
        } else if &bsize != old_blocks.get(&bva).unwrap() {
            workspace.del_code_block(bva);
            workspace.add_code_block(bva, bsize, funcva);
        }
        bcnt += 1;
    }
    workspace.set_function_meta(funcva, "Size", size);
    workspace.set_function_meta(funcva, "BlockCount", bcnt);
    workspace.set_function_meta(funcva, "InstructionCount", opcount);
    // workspace.set_function_meta(funcva, "MnemDist", mnem.get(0).unwrap());
}

pub trait Analyzer {
    fn analyze(&self, workspace: VivWorkspace);
}

impl Debug for dyn Analyzer + 'static {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Analyzer").finish()
    }
}

#[derive(Clone, Debug)]
pub struct AnalysisModTracker {
    analyzers: Vec<Rc<dyn Analyzer>>,
}

impl AnalysisModTracker {
    pub fn new() -> Self {
        AnalysisModTracker {
            analyzers: Vec::new(),
        }
    }

    pub fn register_analyzer(&mut self, analyzer: Rc<dyn Analyzer>) {
        self.analyzers.push(analyzer);
    }

    pub fn start_analysis(&self, workspace: VivWorkspace) {
        for analyzer in self.analyzers.clone() {
            analyzer.analyze(workspace.clone());
        }
    }
}

impl Default for AnalysisModTracker {
    fn default() -> Self {
        Self::new()
    }
}

pub struct EntryPointsAnalyzer;

impl Default for EntryPointsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl EntryPointsAnalyzer {
    pub fn new() -> Self {
        EntryPointsAnalyzer {}
    }
}

impl Analyzer for EntryPointsAnalyzer {
    fn analyze(&self, mut workspace: VivWorkspace) {
        workspace.process_entry_points();
    }
}

pub struct RelocationsAnalyzer;

impl Default for RelocationsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl RelocationsAnalyzer {
    pub fn new() -> Self {
        RelocationsAnalyzer {}
    }
}

impl Analyzer for RelocationsAnalyzer {
    fn analyze(&self, mut workspace: VivWorkspace) {
        println!("INside RELOCATIONS ANALYZER.");
        for (fname, vaoff, rtype, data, size) in workspace.get_relocations() {
            let imgbase = workspace.get_file_meta(fname.as_str(), "imagebase");
            let va = imgbase + vaoff;
            if rtype == RTYPE_BASERELOC && !workspace.is_location(va) {
                workspace.make_pointer(va, None, true);
            } else if rtype == RTYPE_BASEOFF && !workspace.is_location(va) {
                workspace.make_pointer(va, None, true);
            }
        }
    }
}

pub struct StringConstantAnalyzer;

impl Default for StringConstantAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl StringConstantAnalyzer {
    pub fn new() -> Self {
        StringConstantAnalyzer {}
    }
}

impl Analyzer for StringConstantAnalyzer {
    fn analyze(&self, mut workspace: VivWorkspace) {
        debug!(
            "Analyzing string constants, {:?}",
            workspace.get_functions()
        );
        for fva in workspace.get_functions() {
            for (mut va, size, func_va, _) in workspace.get_function_blocks(fva) {
                let maxva = va + size;
                while va < maxva {
                    let op = workspace.parse_op_code(va);
                    if let Some(op) = op {
                        for o in op.opers.clone() {
                            if o.is_deref() {
                                continue;
                            }
                            let reference = o.get_oper_value(op.clone(), None);
                            if reference.is_none() {
                                continue;
                            }
                            let loc = workspace.get_location(reference.as_ref().cloned().unwrap());
                            if loc.is_some()
                                && [LOC_UNI, LOC_STRING].contains(&loc.as_ref().cloned().unwrap().2)
                            {
                                continue;
                            }
                            if !(!workspace
                                .get_xrefs_to(reference.as_ref().cloned().unwrap(), None)
                                .is_empty()
                                && !workspace
                                    .get_xrefs_from(reference.as_ref().cloned().unwrap(), None)
                                    .is_empty())
                            {
                                continue;
                            }
                            if workspace
                                .get_segment(reference.as_ref().cloned().unwrap())
                                .is_none()
                            {
                                continue;
                            }
                            let mut sz =
                                workspace.detect_unicode(reference.as_ref().cloned().unwrap());
                            if sz > 0 {
                                workspace
                                    .make_unicode(reference.as_ref().cloned().unwrap(), Some(sz));
                            } else {
                                sz = workspace.detect_string(reference.as_ref().cloned().unwrap());
                                if sz > 0 {
                                    workspace.make_string(reference.as_ref().cloned().unwrap(), sz);
                                }
                            }
                        }
                        va += op.len() as i32;
                    }
                }
            }
        }
    }
}
