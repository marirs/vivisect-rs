#![allow(dead_code, unused, clippy::type_complexity)]

use crate::{
    analysis::{analyze_function, AnalysisModTracker, Analyzer},
    constants::{
        ARCH_DEFAULT, CB_FUNCVA, ENDIAN_LSB, LOC_IMPORT, LOC_NUMBER, LOC_OP, LOC_POINTER,
        LOC_STRING, LOC_UNI, LOC_VFTABLE, L_LTYPE, L_SIZE, L_TINFO, L_VA, MM_EXEC, MM_READ,
        MM_WRITE, REBASE_TYPES, REF_PTR, SEG_FNAME, VASET_ADDRESS, VASET_COMPLEX, VASET_INTEGER,
        VASET_STRING, VTE_MASK, VWE_ADDFREF, VWE_ADDMMAP, VWE_ADDRELOC, VWE_ADDVASET,
        VWE_AUTOANALFIN, VWE_COMMENT, VWE_DELRELOC, VWE_SETVASETROW, XR_RTYPE,
    },
    context::VivCodeFlowContext,
    emulator::{Emulator, GenericEmulator, ImmedOper, OpCode, RegisterOper},
    memory::Memory,
    page_lookup::MapLookUp,
    parser::parse_file,
    utils::{align, guess_format_filename},
    Object,
};
use chrono::Local;
use log::{debug, error, info, warn};
use std::{collections::HashMap, fmt::format, fs, path::Path, rc::Rc};

/// VivWorkspace is the heart of vivisect_rs's binary analysis. Most APIs accept a VivWorkspace
/// as their first parameter, and the workspace is responsible for all the user facing functions
/// of getters/adders, running analysis passes, making the various locations, loading files, and
/// more.
#[derive(Clone, Debug)]
pub struct VivWorkspace {
    pub sample_path: String,
    analysis_tracker: AnalysisModTracker,
    viv_home: String,
    // pub object: Object,
    loclist: Vec<(i32, i32, i32, Vec<(i32, i32)>)>,
    pub arch: u32,
    segments: Vec<(i32, i32, String, String)>,
    pub locmap: MapLookUp,
    pub blockmap: MapLookUp,
    pub library_functions: Vec<(String, i32)>,
    pub strings: Vec<(String, i32)>,
    exports: Vec<i32>,
    imports: Vec<i32>,
    codeblocks: Vec<(i32, i32, i32, Vec<(i32, i32)>)>,
    relocations: Vec<(String, i32, i32, Vec<u8>, i32)>,
    pub _dead_data: Vec<(String, i32)>,
    _map_defs: Vec<(i32, i32, (i32, i32, i32, String), Vec<u8>)>,
    iscode: HashMap<String, String>,
    xrefs: Vec<(i32, i32, i32, i32)>,
    xrefs_by_to: HashMap<i32, Vec<(i32, i32, i32, i32)>>,
    xrefs_by_from: HashMap<i32, Vec<(i32, i32, i32, i32)>>, // XXX - make config option,
    greedycode: i32,
    metadata: HashMap<String, Option<String>>,
    comments: HashMap<i32, String>, // Comment by VA.,
    symhints: HashMap<String, String>,
    filemeta: HashMap<String, HashMap<String, i32>>, // Metadata Dicts stored by filename,
    transmeta: HashMap<String, String>,              // Metadata that is *not* saved/evented,
    // cfctx : VivCodeFlowContext,
    va_by_name: HashMap<String, i32>,
    name_by_va: HashMap<i32, String>,
    codeblocks_by_funcva: HashMap<i32, Vec<(i32, i32, i32, Vec<(i32, i32)>)>>,
    exports_by_va: HashMap<String, String>,
    colormaps: HashMap<String, String>,
    vasetdefs: HashMap<String, String>,
    // Virtual address sets, Holds the name, and a tuple of definitions and rows.
    vasets: HashMap<String, (Option<Vec<(String, i32)>>, Vec<i32>)>,
    reloc_by_va: HashMap<i32, i32>,
    func_args: HashMap<String, String>,
    funcmeta: HashMap<i32, HashMap<String, i32>>, // Function metadata stored in the workspace,
    frefs: HashMap<(i32, i32), String>,           // Extended analysis modules,
    amods: HashMap<String, String>,
    amodlist: Vec<String>,
    // Extended *function* analysis modules,
    fmods: HashMap<String, String>,
    fmodlist: Vec<String>,
    chan_lookup: HashMap<i32, (i32, i32)>,
    nextchanid: i32,
    _cached_emus: HashMap<String, String>, // The function entry signature decision tree,
    // FIXME add to export,
    // sigtree : e_bytesig.SignatureTree(),
    siglist: Vec<String>,
    _op_cache: HashMap<(i32, u32, Vec<u8>), Option<u32>>,
    p_size: i32,
    endianess: i32,
}

impl VivWorkspace {
    /// Create a new workspace.
    /// - confdir: A path to a directory to save/load vivisect_rs's analysis configuration options (options will be saved to/loaded from the viv.json file in the directory. Thede fault: $HOME/.viv/
    /// - autosave (boolean): If true, autosave any configuration changes to the <confdir>/viv.json upon changing them. Default: False
    pub fn new(confdir: &str, autosave: bool) -> Self {
        let mut workspace = VivWorkspace {
            sample_path: String::new(),
            viv_home: "".to_string(),
            loclist: Vec::new(),
            // object: Object::Unknown(0),
            // cfctx: VivCodeFlowContext::new()
            analysis_tracker: AnalysisModTracker::new(),
            arch: ARCH_DEFAULT,
            locmap: MapLookUp::new(),
            blockmap: MapLookUp::new(),
            library_functions: Vec::new(),
            segments: Vec::new(),
            exports: Vec::new(),
            imports: Vec::new(),
            codeblocks: Vec::new(),
            relocations: Vec::new(),
            _dead_data: Vec::new(),
            _map_defs: Vec::new(),
            iscode: Default::default(),
            xrefs: Vec::new(),
            xrefs_by_to: Default::default(),
            xrefs_by_from: Default::default(),
            greedycode: 0,
            metadata: Default::default(),
            comments: Default::default(),
            symhints: Default::default(),
            filemeta: Default::default(),
            transmeta: Default::default(),
            // cfctx: (),
            va_by_name: Default::default(),
            name_by_va: Default::default(),
            codeblocks_by_funcva: Default::default(),
            exports_by_va: Default::default(),
            colormaps: Default::default(),
            vasetdefs: Default::default(),
            vasets: Default::default(),
            reloc_by_va: Default::default(),
            func_args: Default::default(),
            funcmeta: Default::default(),
            frefs: Default::default(),
            amods: Default::default(),
            amodlist: Vec::new(),
            fmods: Default::default(),
            fmodlist: Vec::new(),
            chan_lookup: Default::default(),
            nextchanid: 0,
            _cached_emus: Default::default(),
            // sigtree: (),
            siglist: Vec::new(),
            _op_cache: Default::default(),
            p_size: 0,
            endianess: ENDIAN_LSB,
            strings: Vec::new(),
        };
        // Some core meta types that exist
        workspace.set_meta("NoReturnApis", None);
        // workspace.set_meta("SymbolikImportEmulation", None);

        // Default to basic file storage
        workspace.set_meta(
            "StorageModule",
            Some("vivisect_rs.storage.basicfile".to_string()),
        );
        // A dd some vasets to use in analysis
        workspace.add_vaset("EntryPoints", vec![("va", VASET_ADDRESS)]);
        workspace.add_vaset("NoReturnCalls", vec![("va", VASET_ADDRESS)]);
        workspace.add_vaset(
            "Emulation Anomalies",
            vec![("va", VASET_ADDRESS), ("Message", VASET_STRING)],
        );
        workspace.add_vaset(
            "Bookmarks",
            vec![("va", VASET_ADDRESS), ("Bookmark Name", VASET_STRING)],
        );
        workspace.add_vaset(
            "DynamicBranches",
            vec![
                ("va", VASET_ADDRESS),
                ("opcode", VASET_STRING),
                ("bflags", VASET_INTEGER),
            ],
        );
        workspace.add_vaset(
            "SwitchCases",
            vec![
                ("va", VASET_ADDRESS),
                ("setup_va", VASET_ADDRESS),
                ("Cases", VASET_INTEGER),
            ],
        );
        workspace.add_vaset(
            "PointersFromFile",
            vec![
                ("va", VASET_ADDRESS),
                ("target", VASET_ADDRESS),
                ("file", VASET_STRING),
                ("comment", VASET_STRING),
            ],
        );
        workspace.add_vaset(
            "CodeFragments",
            vec![("va", VASET_ADDRESS), ("calls_from", VASET_COMPLEX)],
        );
        workspace.add_vaset("EnumCodeFunctions", vec![("va", VASET_ADDRESS)]);
        workspace.add_vaset(
            "FuncWrappers",
            vec![("va", VASET_ADDRESS), ("wrapped_va", VASET_ADDRESS)],
        );

        workspace
    }

    pub fn get_pointer_size(&self) -> i32 {
        self.p_size
    }

    /// Return the GUID for this workspace.  Every newly created VivWorkspace
    /// should have a unique GUID, for identifying a particular workspace for
    /// a given binary/process-space versus another created at a different
    /// time.  Filesystem-copies of the same workspace will have the same GUID
    /// by design.  This easily allows for workspace-specific GUI layouts as
    /// well as comparisons of Server-based workspaces to the original file-
    /// based workspace used to store to the server.
    pub fn get_viv_guid(&mut self, generate: bool) -> Option<String> {
        let mut viv_guid: Option<String> = self.get_meta("GUID");
        if viv_guid.is_none() && generate {
            viv_guid = Some(String::new());
            self.set_meta("GUID", viv_guid.clone());
        }
        viv_guid
    }

    pub fn load_workspace(&mut self, workspace_name: &str) {
        let module_name = self.get_meta("StorageModule");
        // let module = self.load_module(module_name.as_ref().cloned().unwrap().as_str());
        // module.load_workspace(self, workspace_name);
        self.set_meta("StorageName", Some(workspace_name.to_string()));
        // The event list thus far came *only* from the load...
        self.create_save_mark();
        // Snap in our analysis modules
        self.snap_in_analysis_modules();
    }

    pub fn get_meta(&self, meta_name: &str) -> Option<String> {
        if let Some(t) = self.metadata.get(&meta_name.to_string()) {
            return t.clone();
        }
        None
    }

    pub fn set_meta(&mut self, meta_name: &str, meta_value: Option<String>) {
        self.metadata.insert(
            meta_name.to_string(),
            if meta_value.is_some() {
                meta_value
            } else {
                None
            },
        );
    }

    /// Add a reference from the operand at virtual address 'va'
    /// index 'idx' to a function local offset.  Positive values
    /// (beginning with 0) are considered argument references.  Negative
    /// values are considered function local storage and are relative to
    /// the stack pointer at function entry.
    pub fn add_fref(&mut self, fva: i32, va: i32, indx: i32, val: i32) {
        todo!();
        // self.fire_event(VWE_ADDFREF, (va, indx, val));
    }

    /// Get back the fref value (or None) for the given operand index
    /// from the instruction at va.
    pub fn get_fref(&mut self, va: i32, indx: i32) -> Option<String> {
        self.frefs.get(&(va, indx)).cloned()
    }

    /// Get an instance of a WorkspaceEmulator for this workspace.
    /// Use logread/logwrite to enable memory access tracking.
    pub fn get_emulator(&mut self, low_write: bool, taint_byte: &[u8]) -> GenericEmulator {
        let plat = self.get_meta("Platform");
        let arch = self.get_meta("Architecture");
        GenericEmulator::new(self.clone())
    }

    /// Set the human readable comment for a given virtual.
    /// Comments will be displayed by the code renderer, and
    /// are an important part of this balanced breakfast.
    /// Example:
    /// vw.set_comment(callva, "This actually calls FOO...")
    pub fn set_comment(&mut self, va: i32, comment: &str, check: bool) {
        if check && self.comments.get(&va).is_some() {
            return;
        }
        todo!();
        // self.fire_event(VWE_COMMENT, (va, comment));
    }

    /// Returns the comment string (or None) for a given
    /// virtual address.
    /// Example:
    /// cmnt = vw.get_comment(va)
    /// println!("COMMENT: {}", cmnt)
    pub fn get_comment(&self, va: i32) -> String {
        self.comments.get(&va).unwrap().clone()
    }

    /// Retrieve all the comments in the viv workspace as
    /// (va, cmnt) tuples.
    /// Example:
    /// for (va, cmnt) in vw.get_comments(){
    ///     println!("Comment at {}: {}", va, cmnt)
    pub fn get_comments(&self) -> HashMap<i32, String> {
        self.comments.clone()
    }

    /// Add a relocation entry for tracking.
    /// Expects data to have whatever is necessary for the reloc type. eg. addend
    pub fn add_relocation(
        &mut self,
        va: i32,
        r_type: i32,
        data: Option<Vec<u8>>,
        mut size: Option<i32>,
    ) -> Option<i32> {
        let mmap: Option<(i32, i32, i32, String)> = self.get_memory_map(va);
        if mmap.is_none() {
            warn!("add_relocation: No matching map found for {}", va);
            return None;
        }
        let (mmva, mmsz, mmperm, fname) = mmap.unwrap();
        let imgbase: i32 = self.get_file_meta(fname.as_str(), "imagebase");
        let offset = va - imgbase;
        let ext = data.as_ref().cloned().unwrap();
        if size.is_none() {
            size = Some(self.p_size);
        }
        let imgbase = self.get_file_meta(fname.as_str(), "imagebase");
        let rva = imgbase + offset;
        self.reloc_by_va.insert(rva, r_type);
        self.relocations.push((
            fname,
            offset,
            r_type,
            data.as_ref().cloned().unwrap(),
            size.as_ref().cloned().unwrap(),
        ));
        // FIXME Should be careful with this because if we add more REBASE_TYPES we break unless we add the added check. We could possibly just make REBASE_TYPES a vector and check if the vec contains the r_type.
        if REBASE_TYPES.0 == r_type || REBASE_TYPES.1 == r_type {
            let ptr = imgbase + ext.len() as i32;
            if ptr != (ptr & size.as_ref().cloned().unwrap()) {
                warn!("Relocations calculated a bad pointer: {:#0x} (imgbase: {:#0x}) (Relocation: {})", ptr, imgbase, r_type);
            }
            let mem_val = self.read_mem_value(rva, size.as_ref().cloned().unwrap());
            if mem_val.is_some() && ptr != mem_val.unwrap() {
                self.write_mem_value(rva, ptr, size.as_ref().cloned().unwrap());
            }
        }
        // self.fire_event(VWE_ADDRELOC, (fname.as_str(), offset, r_type, Some(ext), size));
        self.get_relocation(va)
    }

    /// Delete a tracked relocation.
    pub fn del_relocation(&mut self, va: i32, full: bool) -> Option<i32> {
        let mmap: Option<(i32, i32, i32, String)> = self.get_memory_map(va);
        if mmap.is_none() {
            warn!("del_relocation: No matching map found for {}", va);
            return None;
        }
        let (mmva, mmsz, mmperm, fname) = mmap.unwrap();
        let reloc: Option<i32> = self.get_relocation(va);
        // if reloc.is_none() {
        //     return None;
        // }
        reloc?;
        let exp = reloc.as_ref().cloned();
        todo!();
        // self.fire_event(VWE_DELRELOC, (fname.to_string(), va, exp.clone(), full));
        reloc
    }

    /// Get the current list of relocation entries.
    pub fn get_relocations(&self) -> Vec<(String, i32, i32, Vec<u8>, i32)> {
        self.relocations.clone()
    }

    /// Return the type of relocation at the specified
    /// VA or None if there isn't a relocation entry for
    /// the address.
    pub fn get_relocation(&self, va: i32) -> Option<i32> {
        self.reloc_by_va.get(&va).cloned()
    }

    pub fn is_location(&self, va: i32) -> bool {
        self.get_location(va).is_some()
    }

    pub fn make_pointer(
        &mut self,
        va: i32,
        mut tova: Option<i32>,
        follow: bool,
    ) -> Option<(i32, i32, i32, Vec<(i32, i32)>)> {
        let loctup = self.get_location(va);
        if loctup.is_some() {
            if loctup.as_ref().cloned().unwrap().2 != LOC_POINTER
                || loctup.as_ref().cloned().unwrap().0 != va
            {
                warn!("{:#0x} Attempting to make a pointer wher another location object exists(of type {})", va, self.repr_location(loctup));
            }
            return None;
        }
        let p_size = self.p_size;
        self.add_xref(va, tova.as_ref().cloned().unwrap(), REF_PTR, 0);
        let ploc = self.add_location(va, p_size, LOC_POINTER, None);
        if tova.is_none() {
            tova = self.cast_pointer(va);
        }
        if follow && self.is_valid_pointer(tova.as_ref().cloned().unwrap()) {
            self.follow_pointer(tova.as_ref().cloned().unwrap());
        }
        Some(ploc)
    }

    pub fn add_xref(&mut self, from_va: i32, to_va: i32, ref_type: i32, r_flags: i32) {
        let reference = (from_va, to_va, ref_type, r_flags);
        if self.get_xrefs_from(from_va, None).contains(&reference) {
            return;
        }
        let mut xr_to = self.xrefs_by_to.get(&to_va).cloned();
        let mut xr_from = self.xrefs_by_from.get(&from_va).cloned();
        if xr_to.is_none() {
            xr_to = Some(Vec::new());
            self.xrefs_by_to
                .insert(to_va, xr_to.as_ref().cloned().unwrap());
        }
        if xr_from.is_none() {
            xr_from = Some(Vec::new());
            self.xrefs_by_from
                .insert(from_va, xr_from.as_ref().cloned().unwrap());
        }
        if !xr_to.as_ref().cloned().unwrap().contains(&reference) {
            xr_to.unwrap().push(reference);
            xr_from.unwrap().push(reference);
            self.xrefs.push(reference);
        }
    }

    pub fn add_location(
        &mut self,
        va: i32,
        size: i32,
        ltype: i32,
        tinfo: Option<Vec<(i32, i32)>>,
    ) -> (i32, i32, i32, Vec<(i32, i32)>) {
        let ltup = (va, size, ltype, tinfo.as_ref().cloned().unwrap());
        self.locmap.set_map_lookup(va, size, Some(ltup.clone()));
        self.loclist.push(ltup.clone());
        ltup
    }

    pub fn cast_pointer(&self, va: i32) -> Option<i32> {
        todo!()
    }

    pub fn follow_pointer(&self, va: i32) {
        todo!()
    }

    // pub fn export_workspace(&self) {
    //     self.event_list.clone()
    // }

    pub fn save_workspace(&self) {
        todo!()
    }

    /// Return ana event, event info tuple.
    pub fn wait_for_event(&self, chan_id: i32) {
        let q = self.chan_lookup.get(&chan_id);
        if q.is_none() {
            panic!("Invalid channel");
        }
    }

    /// Remove a previously allocated event channel fro the workspace.
    pub fn delete_event_channel(&mut self, chanid: i32) {
        self.chan_lookup.remove(&chanid);
    }

    /// Do your best to create a humon readable name for the
    /// value of this pointer.
    /// note: This differs from parent function from envi.cli:
    /// * Locations database is checked
    /// * Strings are returned, not named (partially)
    /// * <function> + 0x<offset> is returned if inside a function
    /// * <filename> + 0x<offset> is returned instead of loc_#####
    pub fn repr_pointer(&mut self, va: i32) -> String {
        if va == 0 {
            return "NULL".to_string();
        }
        let loc = self.get_location(va);
        if let Some(loc_val) = loc {
            let (loc_va, loc_sz, lt, lt_info) = loc_val;
            if vec![LOC_STRING, LOC_UNI].contains(&lt) {
                return self.repr_va(loc_va);
            }
        }
        let (m_base, m_size, m_perm, m_file) = self.get_memory_map(va).unwrap();
        let mut ret = format!("{} {}", m_file, va - m_base);
        let sym: Option<String> = self.get_name(va, true);
        if let Some(sym_val) = sym {
            ret = sym_val;
        }
        ret
    }

    /// A quick way for scripts to get a string for a given virtual address.
    pub fn repr_va(&mut self, va: i32) -> String {
        let loc = self.get_location(va);
        if loc.is_some() {
            return self.repr_location(loc);
        }
        "None".to_string()
    }

    pub fn repr_location(&mut self, loct_up: Option<(i32, i32, i32, Vec<(i32, i32)>)>) -> String {
        if loct_up.is_none() {
            return "No loc info".to_string();
        }

        let (lva, l_size, l_type, t_info) = loct_up.unwrap();
        if l_type == LOC_OP {
            let op = self.parse_op_code(lva);
            return self.repr(op);
        } else if l_type == LOC_STRING {
            return self.repr(self.read_memory(lva, l_size));
        }
        "".to_string()
    }

    /// Roll through entry points and make them into functions(if not already).
    pub fn process_entry_points(&mut self) {
        for eva in self.get_entry_points() {
            if self.is_function(eva) {
                continue;
            }
            if !self.probe_memory(eva, 1, MM_EXEC) {
                continue;
            }
            debug!("processEntryPoint: {:#0X}", eva);
            self.make_function(eva, None, ARCH_DEFAULT as i32);
        }
    }

    /// Add an entry point to the definition for the given file.  This
    /// will hint the analysis system to create functions when analysis
    /// is run.
    /// NOTE: No analysis is triggered by this function.
    pub fn add_entry_point(&mut self, va: i32) {
        self.set_va_set_row("EntryPoints", vec![va]);
    }

    /// Use this API to update the row data for a particular
    /// entry in the VA set.
    pub fn set_va_set_row(&mut self, name: &str, row_tup: Vec<i32>) {
        if let Some(defs_rows_tuple) = self.vasets.get(&name.to_string()) {
            self.vasets
                .insert(name.to_string(), (defs_rows_tuple.clone().0, row_tup));
        } else {
            self.vasets.insert(name.to_string(), (None, row_tup));
        }
    }

    pub fn get_va_set_row(&self, name: &str, va: i32) -> Option<Vec<i32>> {
        let vaset = self.vasets.get(name);
        // if vaset.is_none() {
        //     return None;
        // }
        vaset?;
        Some(vaset.unwrap().clone().1)
    }

    pub fn get_va_set_rows(&self, name: &str) -> Option<Vec<i32>> {
        let x = self.vasets.get(name);
        // if x.is_none() {
        //     return None;
        // }
        x?;
        x.map(|(defs, rows)| rows.clone())
    }

    pub fn add_analyzer(&mut self, analyzer: Rc<dyn Analyzer>) {
        self.analysis_tracker.register_analyzer(analyzer);
    }

    /// Call this to ask any available analysis module.
    pub fn analyze(&mut self, filename: &str) {
        // let  buf = buffer.as_slice();
        // Object::parse(buffer).unwrap();
        let mut buffer = &fs::read(filename).unwrap();
        // Save the analysis.
        match Object::parse(buffer).unwrap() {
            Object::Elf(elf) => {
                println!("elf: {:#?}", &elf);
            }
            Object::PE(pe) => {
                // Set function info
                for import in pe.imports {
                    let mut meta = HashMap::new();
                    // meta.insert("Name".to_string(), import.name);
                    meta.insert("Size".to_string(), import.size as i32);
                    meta.insert("Rva".to_string(), import.rva as i32);
                    meta.insert("Ordinal".to_string(), import.ordinal as i32);
                    meta.insert("Offset".to_string(), import.offset as i32);
                    meta.insert("InstructionCount".to_string(), 0);
                    meta.insert("BlockCount".to_string(), 0);
                    self.funcmeta.insert(import.rva as i32, meta);
                    // iter().map(|x| x.rva as i32).collect::<Vec<_>>()
                }
                // println!("pe: {:#?}", &pe);
            }
            Object::Mach(mach) => {
                println!("mach: {:#?}", &mach);
            }
            Object::Archive(archive) => {
                println!("archive: {:#?}", &archive);
            }
            Object::Unknown(magic) => {
                println!("unknown magic: {:#x}", magic)
            }
        }

        // let start_time = Local::now();
        // // TODO: Call the analysis modules.
        self.analysis_tracker.start_analysis(self.clone());
        // let end_time = Local::now();
        // info!("... analysis complete!  ({} sec) ", (end_time - start_time).num_seconds());
        // self.print_discovered_stats();
    }

    pub fn analyze_function(&self, fva: i32) {
        analyze_function(self.clone(), fva);
    }

    pub fn get_stats(&self) -> HashMap<&str, i32> {
        let mut stats = HashMap::new();
        stats.insert("Functions", self.funcmeta.len() as i32);
        stats.insert("Relocations", self.relocations.len() as i32);
        stats
    }

    pub fn print_discovered_stats(&mut self) {
        let (
            disc,
            un_disc,
            num_xrefs,
            num_locs,
            num_funcs,
            num_blocks,
            num_ops,
            num_unis,
            num_strings,
            num_numbers,
            num_pointers,
            num_vtables,
        ) = self.get_discovered_info();

        let percentage = if disc > 0 && un_disc > 0 {
            disc * 100 / (disc / un_disc)
        } else {
            0
        };
        info!(
            "Percentage of discovered executable surface area: {}% ({} /{})",
            percentage, disc, un_disc
        );
        info!(
            "Xrefs/Blocks/Funcs: ({} / {} / {})",
            num_xrefs, num_blocks, num_funcs
        );
        info!(
            "Locs, Ops/Strings/Unicode/Nums/Ptr/Vtables: ({}: {} / {} / {} / {} / {} / {})",
            num_locs, num_ops, num_strings, num_unis, num_numbers, num_pointers, num_vtables
        );
    }

    /// Returns a tuple of (bytes_with_locations, bytes_without_locations) for all executable maps.
    pub fn get_discovered_info(
        &mut self,
    ) -> (i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32, i32) {
        let mut disc = 0;
        let mut un_disc = 0;
        let m_maps = self.get_memory_maps();

        debug!("MMAPS: {}", m_maps.len());

        for (mva, msz, m_perms, m_name) in m_maps {
            info!("Analyzing Memory map: {:#0x} With {} bytes", mva, msz);
            if !self.is_executable(mva) {
                continue;
            }
            let mut off = 0;
            loop {
                if off >= msz {
                    break;
                }
                let loc = self.get_location(mva + off);
                if loc.is_none() {
                    off += 1;
                    un_disc += 1;
                } else {
                    off += loc.clone().unwrap().2;
                    disc += loc.clone().unwrap().2;
                }
            }

            info!("Finished analyzing memory map: {:#0x}.", mva);
        }
        let num_xrefs = self.get_xrefs(None).len() as i32;
        let num_locs = self.get_locations(None, None).len() as i32;
        let num_funcs = self.get_functions().len() as i32;
        let num_blocks = self.get_code_blocks().len() as i32;
        let num_ops = self.get_locations(Some(LOC_OP), None).len() as i32;
        let num_unis = self.get_locations(Some(LOC_UNI), None).len() as i32;
        let num_strings = self.get_locations(Some(LOC_STRING), None).len() as i32;
        let num_numbers = self.get_locations(Some(LOC_NUMBER), None).len() as i32;
        let num_pointers = self.get_locations(Some(LOC_POINTER), None).len() as i32;
        let num_vtables = self.get_locations(Some(LOC_VFTABLE), None).len() as i32;
        (
            disc,
            un_disc,
            num_xrefs,
            num_locs,
            num_funcs,
            num_blocks,
            num_ops,
            num_unis,
            num_strings,
            num_numbers,
            num_pointers,
            num_vtables,
        )
    }

    pub fn get_xrefs(&self, r_type: Option<i32>) -> Vec<(i32, i32, i32, i32)> {
        if let Some(r_type) = r_type {
            return self
                .xrefs
                .iter()
                .filter(|x| x.2 == r_type)
                .copied()
                .collect::<Vec<_>>();
        }
        self.xrefs.clone()
    }

    pub fn get_functions(&mut self) -> Vec<i32> {
        // Vec::new()
        self.funcmeta.iter().map(|x| *x.0).collect::<Vec<_>>()
    }

    pub fn get_function_meta_dict(&self, va: i32) -> HashMap<String, i32> {
        self.funcmeta.get(&va).unwrap().clone()
    }

    pub fn get_code_blocks(&self) -> Vec<(i32, i32, i32, Vec<(i32, i32)>)> {
        self.codeblocks.clone()
    }

    /// Return a list of location objects from the workspace
    /// of a particular type.
    pub fn get_locations(
        &self,
        ltype: Option<i32>,
        linfo: Option<Vec<(i32, i32)>>,
    ) -> Vec<(i32, i32, i32, Vec<(i32, i32)>)> {
        if ltype.is_none() {
            return self.loclist.clone();
        }
        if linfo.is_none() {
            return self
                .loclist
                .iter()
                .filter(|loc| loc.2 == ltype.as_ref().cloned().unwrap())
                .cloned()
                .collect::<Vec<_>>();
        }
        self.loclist
            .iter()
            .filter(|loc| {
                loc.2 == ltype.as_ref().cloned().unwrap()
                    && loc.3 == linfo.as_ref().cloned().unwrap()
            })
            .cloned()
            .collect::<Vec<_>>()
    }

    pub fn repr<T>(&self, op: T) -> String {
        todo!()
    }

    pub fn snap_in_analysis_modules(&self) {}

    pub fn get_function_blocks(&mut self, func_va: i32) -> Vec<(i32, i32, i32, Vec<(i32, i32)>)> {
        let mut ret = self.codeblocks_by_funcva.get(&func_va).cloned();
        if ret.is_none() {
            ret = Some(Vec::new());
        }
        ret.unwrap()
    }

    /// Get a list of xrefs which point to the given va. Optionally,
    /// specify an rtype to get only xrefs of that type.
    pub fn get_xrefs_to(&self, va: i32, r_type: Option<i32>) -> Vec<(i32, i32, i32, i32)> {
        let mut ret = Vec::new();
        let xrefs = self.xrefs_by_to.get(&va);
        if xrefs.is_none() {
            return ret;
        }
        if r_type.is_none() {
            return xrefs.as_ref().cloned().unwrap().clone();
        }
        xrefs
            .as_ref()
            .cloned()
            .unwrap()
            .iter()
            .filter(|x_tup| x_tup.2 == r_type.as_ref().cloned().unwrap())
            .copied()
            .collect::<Vec<_>>()
    }

    /// Return a list of tuples for the xrefs whose origin is the
    /// specified va.  Optionally, only return xrefs whose type
    /// field is rtype if specified.
    /// example:
    /// for fromva, tova, rtype, rflags in vw.getXrefsFrom(0x41414141):
    /// dostuff(tova)
    pub fn get_xrefs_from(&self, va: i32, r_type: Option<i32>) -> Vec<(i32, i32, i32, i32)> {
        let mut ret = Vec::new();
        let xrefs = self.xrefs_by_from.get(&va);
        if xrefs.is_none() {
            return ret;
        }
        if r_type.is_none() {
            return xrefs.as_ref().cloned().unwrap().clone();
        }
        xrefs
            .as_ref()
            .cloned()
            .unwrap()
            .iter()
            .filter(|x_tup| x_tup.2 == r_type.as_ref().cloned().unwrap())
            .copied()
            .collect::<Vec<_>>()
    }

    pub fn get_code_block(&self, va: i32) -> Option<(i32, i32, i32, Vec<(i32, i32)>)> {
        self.blockmap.get_map_lookup(va)
    }

    pub fn add_code_block(&self, p0: i32, p1: &i32, p2: i32) {
        todo!()
    }

    pub fn del_code_block(&mut self, va: i32) {
        let cb = self.get_code_block(va);
        if cb.is_none() {
            panic!("Unknown code block: {:#0x}", va);
        }
        self.codeblocks.remove(
            self.codeblocks
                .iter()
                .position(|x| *x == cb.as_ref().cloned().unwrap())
                .unwrap(),
        );
        let cb_index = self
            .codeblocks_by_funcva
            .get(&cb.as_ref().cloned().unwrap().0)
            .unwrap()
            .iter()
            .position(|x| x.clone() == cb.as_ref().cloned().unwrap())
            .expect("Code block not present.");
        self.codeblocks_by_funcva
            .get_mut(&cb.as_ref().cloned().unwrap().0)
            .unwrap()
            .remove(cb_index);
        self.blockmap
            .set_map_lookup(va, cb.as_ref().cloned().unwrap().1, None);
    }

    pub fn set_function_meta(&mut self, funcva: i32, key: &str, val: i32) {
        if !self.is_function(funcva) {
            panic!("Invalid function: {}", funcva);
        }
        let mut m = self.funcmeta.get(&funcva);
        if m.is_some() {
            let mut copy = m.as_ref().cloned().unwrap().clone();
            copy.insert(key.to_string(), val);
            m = Some(&copy);
        }
        let mcbname = format!(
            "_fmcb_{}",
            key.split(':').collect::<Vec<_>>().first().unwrap()
        );
    }

    /// Parse an opcode from the specified virtual address.
    /// Example: op = m.parseOpcode(0x7c773803, skipcache=True)
    /// Set skipcache=True in order to bypass the opcode cache and force a reparsing of bytes
    pub fn parse_op_code(&mut self, va: i32) -> Option<OpCode> {
        let (off, b) = self.get_byte_def(va);
        let loct_up = self.get_location(va);
        let mut arch = ARCH_DEFAULT;
        if loct_up.is_some() {
            let loct_up_unwrapped = loct_up.as_ref().cloned().unwrap();
            if !loct_up_unwrapped.3.is_empty() && loct_up_unwrapped.2 == LOC_OP {
                // arch = loct_up_unwrapped.3;
            }
        }
        let key = (va, arch, b[..16].to_vec());
        let valu = *self._op_cache.get(&key).unwrap();
        self._op_cache.insert(key, valu);
        // FIXME Return a properly formed opcode
        Some(OpCode::new(
            va,
            0,
            "GENERIC",
            0,
            0,
            vec![Rc::new(RegisterOper {}), Rc::new(ImmedOper {})],
        ))
    }

    /// If the address appears to be the start of a unicode string, then
    /// return the string length in bytes, else return -1.
    /// This will return true if the memory location is likely
    /// *simple* UTF16-LE unicode (<ascii><0><ascii><0><0><0>).
    pub fn detect_unicode(&self, va: i32) -> i32 {
        let (offset, bytes) = self.get_byte_def(va);
        let max_len = bytes.len() as i32 - offset;
        let mut count = 0;
        if max_len < 2 {
            return -1;
        }
        let charset = bytes.get((offset + 1) as usize).unwrap();
        while count < max_len {
            /// If we hit another thing, then probably not.
            /// Ignore when count==0 so detection can check something
            /// already set as a location.
            if count > 0 {
                let loc = self.get_location(va + count);
                if loc.is_some() {
                    if loc.as_ref().unwrap().2 == LOC_UNI {
                        if loc.as_ref().unwrap().0 == va {
                            return loc.as_ref().cloned().unwrap().1;
                        }
                        if *bytes.get((offset + count) as usize).unwrap() != 0 {
                            return count + loc.as_ref().cloned().unwrap().1;
                        }
                        return loc.as_ref().cloned().unwrap().0 - (va + count)
                            + loc.as_ref().cloned().unwrap().1;
                    }
                    return -1;
                }
            }
            let c0 = *bytes.get((offset + count) as usize).unwrap();
            if offset + count + 1 >= bytes.len() as i32 {
                return -1;
            }
            let c1 = *bytes.get((offset + count + 1) as usize).unwrap();
            //  If we find our null terminator after more
            // than 4 chars, we're probably a real string
            if c0 == 0 {
                if count > 8 {
                    return count;
                }
                return -1;
            }
            // If the first byte char isn't printable, then
            //  we're probably not a real "simple" ascii string
            if !char::from(c0).is_ascii() {
                return -1;
            }
            count += 2;
        }
        -1
    }

    pub fn is_probably_unicode(&self, va: i32) -> bool {
        self.detect_unicode(va) > 0
    }

    pub fn make_unicode(
        &mut self,
        va: i32,
        mut size: Option<i32>,
    ) -> (i32, i32, i32, Vec<(i32, i32)>) {
        if size.is_none() {
            size = self.uni_string_size(va);
        }
        let size = size.unwrap();
        if size <= 0 {
            error!("Invalid unicode size: {}", size);
        }
        let subs = self.get_substrings(va, size, LOC_UNI);
        let (p_va, p_size, t_info) = self.get_str_info(va, size, subs);
        if self.get_name(va, false).is_none() {
            let m = self
                .read_memory(va, size - 1)
                .unwrap()
                .iter()
                .map(|x| {
                    if vec![*x] == "\n".as_bytes() || vec![*x] == "\0".as_bytes() {
                        "".as_bytes().to_vec()
                    } else {
                        vec![*x]
                    }
                })
                .collect::<Vec<_>>();
            self.make_name(
                va,
                format!("wstr_{:?}_{:#0x}", m[..16].to_vec(), va),
                false,
                false,
            );
        }
        self.add_location(p_va, p_size, LOC_UNI, t_info)
    }

    /// An optimized routine which returns the existing
    /// segment bytes sequence without creating a new
    /// string object *AND* an offset of va into the
    /// buffer.  Used internally for optimized memory
    /// handling.  Returns (offset, bytes)
    pub fn get_byte_def(&self, va: i32) -> (i32, Vec<u8>) {
        for map_def in self._map_defs.clone() {
            let (mva, mmaxva, mmap, mbytes) = map_def;
            if mva <= va && va < mmaxva {
                let offset = va - mva;
                return (offset, mbytes);
            }
        }
        panic!("Not found in provided addresses.");
    }

    pub fn get_location(&self, va: i32) -> Option<(i32, i32, i32, Vec<(i32, i32)>)> {
        let loc = self.locmap.get_map_lookup(va);
        // if loc.is_none() {
        //     return None;
        // }
        loc.as_ref()?;
        return if vec![LOC_STRING, LOC_UNI].contains(&loc.as_ref().cloned().unwrap().2) {
            if loc.as_ref().cloned().unwrap().3.is_empty() {
                return loc;
            }
            let mut subs = loc.as_ref().cloned().unwrap().3;
            subs.sort_by(|x, y| x.partial_cmp(y).unwrap());
            let mut ltup = loc.as_ref().cloned();
            for (sva, ssize) in subs {
                if sva <= va && va < (sva + ssize) {
                    ltup = Some((sva, ssize, loc.as_ref().cloned().unwrap().2, vec![]));
                }
            }
            ltup
        } else {
            loc
        };
    }

    pub(crate) fn make_code(&self, va: i32, arch: u32, p2: i32) {
        todo!()
    }

    pub(crate) fn del_location(&self, va: i32) {
        todo!()
    }

    pub fn get_entry_points(&self) -> Vec<i32> {
        let entry_points = self.get_va_set_rows("EntryPoints").unwrap();
        info!("Entry points {:?}", entry_points);
        entry_points
    }

    pub fn get_file_meta(&self, filename: &str, key: &str) -> i32 {
        let d = self.filemeta.get(filename);
        if d.is_none() {
            panic!("Invalid File: {}", filename);
        }
        *d.unwrap().get(&key.to_string()).unwrap()
    }

    pub fn set_file_meta(&mut self, fname: String, key: String, val: i32) {
        if !self.filemeta.contains_key(&fname) {
            panic!("Invalid file: {}", fname);
        }
        let mut f = self.filemeta.get_mut(&fname).unwrap();
        f.insert(key, val);
    }

    pub fn get_file_meta_dict(&self, filename: &str) -> HashMap<String, i32> {
        let d = self.filemeta.get(filename);
        if d.is_none() {
            panic!("Invalid File: {}", filename);
        }
        d.unwrap().clone()
    }

    pub fn make_function(&mut self, va: i32, meta: Option<HashMap<String, i32>>, arch: i32) {
        debug!("make_function({:#0x}, {:?}, {:#0x})", va, meta, arch);
        if self.is_function(va) {
            debug!("{:#0x} is already a function. Skipping.", va);
            return;
        }
        if !self.is_valid_pointer(va) {
            panic!("Invalid location provided. {:#0x}", va);
        }
        let loc = self.get_location(va);
        if loc.is_some()
            && !loc.as_ref().cloned().unwrap().3.is_empty()
            && loc.as_ref().cloned().unwrap().2 == LOC_OP
        {
            let arch = loc.as_ref().cloned().unwrap().3;
        }
        self.add_entry_point(va);
        if meta.is_some() {
            for (key, val) in meta.as_ref().cloned().unwrap() {
                self.set_function_meta(va, key.as_str(), val);
            }
        }
    }

    pub fn is_function(&self, func_va: i32) -> bool {
        self.funcmeta.get(&func_va).is_some()
    }

    /// Returns the name of the specified virtual address (or None).
    /// Smart mode digs beyond simple name lookups, as follows:
    /// If va falls within a known function in the workspace, we return "funcname+<delta>".
    /// If not, and the va falls within a mapped binary, we return "filename+<delta>"
    pub fn get_name(&self, va: i32, smart: bool) -> Option<String> {
        let mut name = self.name_by_va.get(&va).cloned();
        if name.is_some() || !smart {
            return name;
        }
        let mut base_va = self.get_function(va).unwrap();
        let mut base_name = self.name_by_va.get(&base_va).cloned();
        if self.is_function(va) {
            base_name = Some(format!("sub_{:#0x}", va));
        }
        if base_name.is_none() {
            base_name = self.get_file_by_va(va);
            // if base_name.is_none() {
            //     return None;
            // }
            base_name.as_ref()?;
            base_va =
                self.get_file_meta(base_name.as_ref().cloned().unwrap().as_str(), "imagebase");
        }
        let delta = va - base_va;
        name = base_name;
        name
    }

    /// Set a readable name for the given location by va. There
    /// *must* be a Location defined for the VA before you may name
    /// it.  You may set a location's name to None to remove a name.
    /// makeuniq allows Vivisect to append some number to make the name unique.
    /// This behavior allows for colliding names (eg. different versions of a function)
    /// to coexist in the same workspace.
    /// default behavior is to fail on duplicate (False).
    pub fn make_name(
        &mut self,
        va: i32,
        mut name: String,
        file_local: bool,
        make_unique: bool,
    ) -> Option<String> {
        if file_local {
            let seg_tup = self.get_segment(va);
            if seg_tup.is_none() {
                warn!(
                    "Failed to find file for {:#0x} ({}) (and file_local != true)",
                    va, name
                );
            } else {
                let fname = seg_tup.as_ref().cloned().unwrap().3;
                if !fname.is_empty() {
                    name = format!("{}.{}", fname, name);
                }
            }
        }
        let old_va: Option<i32> = self.va_by_name(name.clone());
        if old_va.as_ref().cloned().unwrap() == va {
            return None;
        }
        if old_va.is_some() {
            if !make_unique {
                panic!("Duplicate name provided: {}", name);
            } else {
                debug!(
                    "makeName: {} already lives at {:#0x}",
                    name,
                    old_va.as_ref().cloned().unwrap()
                );
                let mut index = 0;
                let mut new_name = format!("{}_{}", name, index);
                let mut new_old_va: Option<i32> = self.va_by_name(new_name.clone());
                while self.va_by_name(new_name.clone()).is_some() {
                    if new_old_va.as_ref().cloned().unwrap() == va {
                        return Some(new_name);
                    }
                    debug!(
                        "makeName: {} already lives at {:#0x}",
                        new_name.clone(),
                        new_old_va.as_ref().cloned().unwrap()
                    );
                    index += 1;
                    new_name = format!("{}_{}", name, index);
                    new_old_va = self.va_by_name(new_name.clone());
                }
                name = new_name;
            }
        }
        // Handle the SETNAME event
        let cur_name = self.name_by_va.get(&va);
        if cur_name.is_some() {
            debug!(
                "Replacing {:#0x}: {} -> {}",
                va,
                cur_name.as_ref().cloned().unwrap(),
                name
            );
            self.va_by_name.remove(cur_name.as_ref().cloned().unwrap());
        }
        self.va_by_name.insert(name.clone(), va);
        self.name_by_va.insert(va, name.clone());
        if self.is_function(va) {
            // Handle if its a function by modifying the call graph
        }
        Some(name)
    }

    pub fn detect_string(&self, va: i32) -> i32 {
        todo!()
    }

    pub fn make_string(&self, va: i32, size: i32) {
        todo!()
    }

    /// Return the VA for this function.  This will search code blocks
    /// and check for a function va.
    pub fn get_function(&self, va: i32) -> Option<i32> {
        if self.funcmeta.get(&va).is_some() {
            return Some(va);
        }
        let cbtup = self.get_code_block(va);
        if let Some(cbtup_val) = cbtup {
            return Some(cbtup_val.2);
        }
        None
    }

    /// Return the size (in bytes) of the unicode string
    /// at the specified location (or -1 if no terminator
    /// is found in the memory map)
    pub fn uni_string_size(&self, va: i32) -> Option<i32> {
        let (offset, bytes) = self.get_byte_def(va);
        let foff = String::from_utf8(bytes)
            .unwrap()
            .find("\x00\x00")
            .map(|x| x as i32);
        if foff.is_some() {
            return foff;
        }
        Some((foff.as_ref().cloned().unwrap() - offset) + 2)
    }

    pub fn get_substrings(&self, va: i32, size: i32, r_type: i32) -> Option<Vec<(i32, i32)>> {
        // rip through the desired memory range to populate any substrings
        let mut subs = Vec::new();
        let end = va + size;
        for offs in (va..end).step_by(1) {
            let loc = self.get_location(offs);
            if loc.is_some()
                && loc.as_ref().cloned().unwrap().2 == LOC_STRING
                && loc.as_ref().cloned().unwrap().0 > va
            {
                subs.push((
                    loc.as_ref().cloned().unwrap().0,
                    loc.as_ref().cloned().unwrap().1,
                ));
                if !loc.as_ref().cloned().unwrap().3.is_empty() {
                    subs.append(&mut loc.as_ref().cloned().unwrap().3);
                }
            }
        }
        Some(subs)
    }

    pub fn get_str_info(
        &self,
        mut va: i32,
        mut size: i32,
        subs: Option<Vec<(i32, i32)>>,
    ) -> (i32, i32, Option<Vec<(i32, i32)>>) {
        let ploc = self.get_location(va);
        let tinfo;
        if ploc.is_some() {
            let mut modified = false;
            let (p_va, p_size, p_type, mut p_info) = ploc.as_ref().cloned().unwrap();
            if !vec![LOC_STRING, LOC_UNI].contains(&p_type) {
                return (va, size, subs);
            }
            if !p_info.contains(&(va, size)) {
                modified = true;
                p_info.push((va, size));
            }
            for (sva, ssize) in subs.as_ref().cloned().unwrap() {
                if !p_info.contains(&(sva, ssize)) {
                    modified = true;
                    p_info.push((sva, ssize));
                }
            }
            tinfo = Some(p_info);
            if modified {
                va = p_va;
                size = p_size;
            }
        } else {
            tinfo = subs;
        }
        (va, size, tinfo)
    }

    pub fn va_by_name(&self, name: String) -> Option<i32> {
        self.va_by_name.get(&name).copied()
    }

    pub fn create_save_mark(&self) {
        todo!()
    }

    pub fn get_file_by_va(&self, va: i32) -> Option<String> {
        let segtup = self.get_segment(va);
        info!("Segment: {:?}", segtup);
        // if segtup.is_none() {
        //     return None;
        // }
        segtup.as_ref()?;
        Some(segtup.unwrap().3)
    }

    pub fn get_segment(&self, va: i32) -> Option<(i32, i32, String, String)> {
        info!("Segments: {:?}", self.segments);
        for seg in self.segments.clone() {
            let (sva, ssize, sname, sfile) = seg.clone();
            if va >= sva && va < (sva + ssize) {
                return Some(seg);
            }
        }
        None
    }

    pub fn add_segment(&mut self, va: i32, size: i32, name: &str, filename: String) {
        self.segments.push((va, size, name.to_string(), filename));
    }

    pub fn get_function_args(&self, va: i32) -> HashMap<String, String> {
        self.func_args.clone()
    }

    pub fn add_vaset(&mut self, name: &str, defs: Vec<(&str, i32)>) {
        self.vasets.insert(
            name.to_string(),
            (
                Some(
                    defs.iter()
                        .map(|(name, val)| (name.to_string(), *val))
                        .collect(),
                ),
                vec![],
            ),
        );
    }

    /// Read the first bytes of the file and see if we can identify the type.
    /// If so, load up the parser for that file type, otherwise raise an exception.
    /// ( if it's a workspace, trigger loadWorkspace() as a convenience )
    /// Returns the basename the file was given on load.
    pub fn load_from_file(
        &mut self,
        filename: &str,
        mut fmt_name: Option<String>,
        base_addr: Option<i32>,
    ) -> String {
        self.sample_path = filename.to_string();
        if fmt_name.is_none() {
            fmt_name = Some(guess_format_filename(filename));
        }
        // if STORAGE_MAP.contains(fmt_name.as_ref().cloned().unwrap()) {
        //     self.set_meta("StorageModule", STORAGE_MAP.get(fmt_name.as_ref().cloned().unwrap()));
        //     self.load_workspace(filename);
        //     return self.norm_filename(filename);
        // }
        // let fname = parse_file(self.clone(), filename, base_addr);
        // fname
        parse_file(self.clone(), filename, base_addr)
    }

    pub fn add_file(&mut self, filename: &str, imagebase: i32, bytes: Vec<u8>) -> String {
        let nname = self.norm_filename(filename);
        if self.filemeta.contains_key(&nname) {
            panic!("Duplicate file name: {}", filename);
        }
        let mut meta = HashMap::new();
        meta.insert("imagebase".to_string(), imagebase);
        // self.set_file_meta(nname.clone(), "OrigName", filename);
        self.filemeta.insert(filename.to_string(), meta);
        nname
    }

    pub fn norm_filename(&self, filename: &str) -> String {
        let mut normname = Path::new(filename).to_path_buf();
        normname = normname.canonicalize().unwrap();
        normname.file_stem().unwrap().to_str().unwrap().to_string()
    }
}

impl Memory for VivWorkspace {
    fn get_endian(&mut self) -> i32 {
        self.endianess
    }

    fn set_endian(&mut self, endianess: i32) {
        self.endianess = endianess
    }

    fn set_mem_architecture(&mut self, arch: u32) {
        self.arch = arch;
    }

    fn get_mem_architecture(&mut self) -> u32 {
        self.arch
    }

    /// Read memory from maps stored in memory maps.
    /// If the read crosses memory maps and fails on a later map, the exception
    /// will show the details of the last map/failure, but should include the
    /// original va (not the size).
    /// _origva is an internal field and should not be used.
    fn read_memory(&self, va: i32, size: i32) -> Option<Vec<u8>> {
        for (m_va, m_max_va, m_map, m_bytes) in self._map_defs.clone() {
            if m_va <= va && va < m_max_va {
                let (m_va, m_size, m_perms, m_fname) = m_map;
                if m_perms & MM_READ == 0 {
                    panic!(
                        "Bad Memory Read (no read permission): {:#0x}: {:#0x} ",
                        va, size
                    );
                }
                let offset = va - m_va;
                let max_read_len = m_size - offset;
                if size > max_read_len {
                    let mut new_bytes = Vec::new();
                    new_bytes.append(
                        &mut m_bytes[offset as usize..].to_vec(),
                        // .iter()
                        // .copied()
                        // // .map(|x| *x)
                        // .collect::<Vec<_>>(),
                    );
                    new_bytes.append(
                        &mut self
                            .read_memory(m_va + m_size, size - max_read_len)
                            .unwrap(),
                    );
                    return Some(new_bytes);
                }
            }
        }
        panic!(
            "Bad memory read (invalid memory address): {:#0x}: {:#0x}",
            va, size
        );
    }

    /// Write memory to maps stored in memory maps.
    /// If the write crosses memory maps and fails on a later map, the exception
    /// will show the details of the last map/failure, but should include the
    /// original va (but not the original size).
    /// In this scenario, writes to the first map will succeed, up until the address of the exception.
    fn write_memory(&mut self, va: i32, bytes: Vec<u8>) {
        let bytes_len = bytes.len() as i32;
        for mut mapdef in self._map_defs.clone() {
            let (mva, mmaxva, mmap, mbytes) = mapdef;
            if mva <= va && va < mmaxva {
                let (mva, msize, mperms, mfname) = mmap;
                if mperms & MM_WRITE == 0 {
                    panic!(
                        "Bad Memory Write (no read permission): {:#0x}: {:#0x} ",
                        va, bytes_len
                    );
                }
                let offset = va - mva;
                let max_write_len = msize - offset;
                if bytes_len > max_write_len {
                    let mut new_bytes = Vec::new();
                    new_bytes.append(
                        &mut mbytes[..offset as usize].to_vec(),
                        // .iter()
                        // .copied()
                        // // .map(|x| *x)
                        // .collect::<Vec<_>>(),
                    );
                    new_bytes.append(
                        &mut bytes[..max_write_len as usize].to_vec(),
                        // .iter()
                        // .copied()
                        // // .map(|x| *x)
                        // .collect::<Vec<_>>(),
                    );
                    mapdef.3 = new_bytes;
                    self.write_memory(
                        mva + msize,
                        bytes[max_write_len as usize..].to_vec(),
                        // .iter()
                        // .copied()
                        // // .map(|x| *x)
                        // .collect::<Vec<_>>(),
                    );
                } else {
                    let mut new_bytes = Vec::new();
                    new_bytes.append(
                        &mut mbytes[..offset as usize].to_vec(),
                        // .iter()
                        // .copied()
                        // // .map(|x| *x)
                        // .collect::<Vec<_>>(),
                    );
                    new_bytes.append(&mut bytes.clone());
                    new_bytes.append(
                        &mut mbytes[(offset + bytes_len) as usize..].to_vec(),
                        // .iter()
                        // .copied()
                        // // .map(|x| *x)
                        // .collect::<Vec<_>>(),
                    );
                    mapdef.3 = new_bytes;
                }
            }
        }
        panic!(
            "Bad memory read (invalid memory address): {:#0x}: {:#0x}",
            va, bytes_len
        );
    }

    fn protect_memory(&mut self, va: i32, size: i32, perms: i32) {
        todo!()
    }

    fn allocate_memory(&mut self, size: i32, perms: i32, suggest_addr: i32) {
        todo!()
    }

    /// Add a memory map to the workspace.  This is the *only* way to
    /// get memory backings into the workspace.
    fn add_memory_map(
        &mut self,
        map_va: i32,
        perms: i32,
        fname: &str,
        mut bytes: Vec<u8>,
        alignment: Option<i32>,
    ) -> i32 {
        debug!(
            "Map VA: {} Perms: {}, fname: {}, bytes: {}",
            map_va,
            perms,
            fname,
            bytes.len()
        );
        // if alignment.is_some() {
        if let Some(a_val) = alignment {
            let cur_len = bytes.len();
            // let new_len: usize = align(cur_len, alignment.unwrap() as usize);
            let new_len: usize = align(cur_len, a_val as usize);
            let delta = new_len - cur_len;
            bytes.append(&mut vec![0x00; delta]);
        }
        let msize = bytes.len() as i32;
        let mmap = (map_va, msize, perms, fname.to_string());
        let hlpr = (map_va, map_va + msize as i32, mmap, bytes);
        self._map_defs.push(hlpr);
        // self.locmap.init_map_lookup(map_va, msize, None);
        msize
    }

    fn get_memory_maps(&mut self) -> Vec<(i32, i32, i32, String)> {
        let mut ret = Vec::new();
        for (mva, mmaxva, mmap, mbytes) in self._map_defs.clone() {
            ret.push(mmap);
        }
        ret
    }

    fn read_memory_format(&mut self, va: i32, fmt: &str) {
        todo!()
    }
}
