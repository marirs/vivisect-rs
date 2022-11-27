//! A PE32 and PE32+ parser
//!

// TODO: panics with unwrap on None for apisetschema.dll, fhuxgraphics.dll and some others

use alloc::vec::Vec;

pub mod characteristic;
pub mod data_directories;
pub mod debug;
pub mod exception;
pub mod export;
pub mod header;
pub mod import;
pub mod optional_header;
pub mod options;
pub mod relocation;
pub mod section_table;
pub mod symbol;
pub mod utils;

use crate::container;
use crate::error;
use crate::strtab;

use log::debug;

#[derive(Debug, Clone)]
/// An analyzed PE32/PE32+ binary
pub struct PE<'a> {
    /// The PE header
    pub header: header::Header,
    /// A list of the sections in this PE binary
    pub sections: Vec<section_table::SectionTable>,
    /// The size of the binary
    pub size: usize,
    /// The number of functions in the binary.
    pub functions: i32,
    /// The name of this `dll`, if it has one
    pub name: Option<&'a str>,
    /// Whether this is a `dll` or not
    pub is_lib: bool,
    /// Whether the binary is 64-bit (PE32+)
    pub is_64: bool,
    /// the entry point of the binary
    pub entry: usize,
    /// The binary's RVA, or image base - useful for computing virtual addreses
    pub image_base: usize,
    /// Data about any exported symbols in this binary (e.g., if it's a `dll`)
    pub export_data: Option<export::ExportData<'a>>,
    /// Data for any imported symbols, and from which `dll`, assets., in this binary
    pub import_data: Option<import::ImportData<'a>>,
    /// The list of exported symbols in this binary, contains synthetic information for easier analysis
    pub exports: Vec<export::Export<'a>>,
    /// The list symbols imported by this binary from other `dll`s
    pub imports: Vec<import::Import<'a>>,
    /// The list of libraries which this binary imports symbols from
    pub libraries: Vec<&'a str>,
    /// Debug information, if any, contained in the PE header
    pub debug_data: Option<debug::DebugData<'a>>,
    /// Exception handling and stack unwind information, if any, contained in the PE header
    pub exception_data: Option<exception::ExceptionData<'a>>,
}

impl<'a> PE<'a> {
    /// Reads a PE binary from the underlying `bytes`
    pub fn parse(bytes: &'a [u8]) -> error::Result<Self> {
        Self::parse_with_opts(bytes, &options::ParseOptions::default())
    }

    /// Reads a PE binary from the underlying `bytes`
    pub fn parse_with_opts(bytes: &'a [u8], opts: &options::ParseOptions) -> error::Result<Self> {
        let header = header::Header::parse(bytes)?;
        debug!("{:#?}", header);
        let offset = &mut (header.dos_header.pe_pointer as usize
            + header::SIZEOF_PE_MAGIC
            + header::SIZEOF_COFF_HEADER
            + header.coff_header.size_of_optional_header as usize);
        let sections = header.coff_header.sections(bytes, offset)?;
        let is_lib = characteristic::is_dll(header.coff_header.characteristics);
        let mut entry = 0;
        let mut image_base = 0;
        let mut exports = vec![];
        let mut export_data = None;
        let mut name = None;
        let mut imports = vec![];
        let mut import_data = None;
        let mut functions = 0;
        let mut libraries = vec![];
        let mut debug_data = None;
        let mut exception_data = None;
        let mut is_64 = false;
        if let Some(optional_header) = header.optional_header {
            entry = optional_header.standard_fields.address_of_entry_point as usize;
            image_base = optional_header.windows_fields.image_base as usize;
            is_64 = optional_header.container()? == container::Container::Big;
            debug!(
                "entry {:#x} image_base {:#x} is_64: {}",
                entry, image_base, is_64
            );
            let file_alignment = optional_header.windows_fields.file_alignment;
            if let Some(export_table) = *optional_header.data_directories.get_export_table() {
                if let Ok(ed) = export::ExportData::parse_with_opts(
                    bytes,
                    export_table,
                    &sections,
                    file_alignment,
                    opts,
                ) {
                    debug!("export data {:#?}", ed);
                    exports = export::Export::parse_with_opts(
                        bytes,
                        &ed,
                        &sections,
                        file_alignment,
                        opts,
                    )?;
                    name = ed.name;
                    debug!("name: {:#?}", name);
                    export_data = Some(ed);
                }
            }
            debug!("exports: {:#?}", exports);
            if let Some(import_table) = *optional_header.data_directories.get_import_table() {
                let id = if is_64 {
                    import::ImportData::parse_with_opts::<u64>(
                        bytes,
                        import_table,
                        &sections,
                        file_alignment,
                        opts,
                    )?
                } else {
                    import::ImportData::parse_with_opts::<u32>(
                        bytes,
                        import_table,
                        &sections,
                        file_alignment,
                        opts,
                    )?
                };
                debug!("import data {:#?}", id);
                if is_64 {
                    imports = import::Import::parse::<u64>(bytes, &id, &sections)?
                } else {
                    imports = import::Import::parse::<u32>(bytes, &id, &sections)?
                }
                functions = imports.len() as i32;
                libraries = id
                    .import_data
                    .iter()
                    .map(|data| data.name)
                    .collect::<Vec<&'a str>>();
                libraries.sort();
                libraries.dedup();
                import_data = Some(id);
            }
            debug!("imports: {:#?}", imports);
            if let Some(debug_table) = *optional_header.data_directories.get_debug_table() {
                debug_data = Some(debug::DebugData::parse_with_opts(
                    bytes,
                    debug_table,
                    &sections,
                    file_alignment,
                    opts,
                )?);
            }

            if header.coff_header.machine == header::COFF_MACHINE_X86_64 {
                // currently only x86_64 is supported
                debug!("exception data: {:#?}", exception_data);
                if let Some(exception_table) =
                    *optional_header.data_directories.get_exception_table()
                {
                    exception_data = Some(exception::ExceptionData::parse_with_opts(
                        bytes,
                        exception_table,
                        &sections,
                        file_alignment,
                        opts,
                    )?);
                }
            }
        }
        Ok(PE {
            header,
            sections,
            functions,
            size: 0,
            name,
            is_lib,
            is_64,
            entry,
            image_base,
            export_data,
            import_data,
            exports,
            imports,
            libraries,
            debug_data,
            exception_data,
        })
    }
}

/// An analyzed COFF object
#[derive(Debug)]
pub struct Coff<'a> {
    /// The COFF header
    pub header: header::CoffHeader,
    /// A list of the sections in this COFF binary
    pub sections: Vec<section_table::SectionTable>,
    /// The COFF symbol table.
    pub symbols: symbol::SymbolTable<'a>,
    /// The string table.
    pub strings: strtab::Strtab<'a>,
}

impl<'a> Coff<'a> {
    /// Reads a COFF object from the underlying `bytes`
    pub fn parse(bytes: &'a [u8]) -> error::Result<Self> {
        let offset = &mut 0;
        let header = header::CoffHeader::parse(bytes, offset)?;
        debug!("{:#?}", header);
        // TODO: maybe parse optional header, but it isn't present for Windows.
        *offset += header.size_of_optional_header as usize;
        let sections = header.sections(bytes, offset)?;
        let symbols = header.symbols(bytes)?;
        let strings = header.strings(bytes)?;
        Ok(Coff {
            header,
            sections,
            symbols,
            strings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Coff;
    use super::PE;

    static INVALID_DOS_SIGNATURE: [u8; 512] = [
        0x3D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00,
        0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01,
        0x4C, 0xCD, 0x21, 0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D,
        0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20,
        0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
        0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x23, 0x31, 0xE2, 0xB1, 0x67, 0x50, 0x8C,
        0xE2, 0x67, 0x50, 0x8C, 0xE2, 0x67, 0x50, 0x8C, 0xE2, 0x3C, 0x38, 0x88, 0xE3, 0x6D, 0x50,
        0x8C, 0xE2, 0x3C, 0x38, 0x8F, 0xE3, 0x62, 0x50, 0x8C, 0xE2, 0x3C, 0x38, 0x89, 0xE3, 0xE0,
        0x50, 0x8C, 0xE2, 0xAC, 0x3F, 0x89, 0xE3, 0x42, 0x50, 0x8C, 0xE2, 0xAC, 0x3F, 0x88, 0xE3,
        0x77, 0x50, 0x8C, 0xE2, 0xAC, 0x3F, 0x8F, 0xE3, 0x6E, 0x50, 0x8C, 0xE2, 0x3C, 0x38, 0x8D,
        0xE3, 0x64, 0x50, 0x8C, 0xE2, 0x67, 0x50, 0x8D, 0xE2, 0x3F, 0x50, 0x8C, 0xE2, 0xE1, 0x20,
        0x85, 0xE3, 0x66, 0x50, 0x8C, 0xE2, 0xE1, 0x20, 0x73, 0xE2, 0x66, 0x50, 0x8C, 0xE2, 0xE1,
        0x20, 0x8E, 0xE3, 0x66, 0x50, 0x8C, 0xE2, 0x52, 0x69, 0x63, 0x68, 0x67, 0x50, 0x8C, 0xE2,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x50, 0x45, 0x00, 0x00, 0x64, 0x86, 0x07, 0x00, 0x5F, 0x41, 0xFC, 0x5E, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x22, 0x00, 0x0B, 0x02, 0x0E, 0x1A, 0x00,
        0xFC, 0x00, 0x00, 0x00, 0xD6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE4, 0x14, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xE0,
        0x68, 0x02, 0x00, 0x03, 0x00, 0x60, 0x81, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xA3, 0x01, 0x00, 0x28,
        0x00, 0x00, 0x00, 0x00, 0xF0, 0x01, 0x00, 0xE0, 0x01, 0x00, 0x00, 0x00, 0xD0, 0x01, 0x00,
        0x60, 0x0F, 0x00, 0x00, 0x00, 0xC4, 0x01, 0x00, 0xF8, 0x46, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x54, 0x06, 0x00, 0x00, 0xF0, 0x91, 0x01, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x92, 0x01, 0x00, 0x30, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x00, 0x48, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    static INVALID_PE_SIGNATURE: [u8; 512] = [
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00,
        0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01,
        0x4C, 0xCD, 0x21, 0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D,
        0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20,
        0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
        0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x23, 0x31, 0xE2, 0xB1, 0x67, 0x50, 0x8C,
        0xE2, 0x67, 0x50, 0x8C, 0xE2, 0x67, 0x50, 0x8C, 0xE2, 0x3C, 0x38, 0x88, 0xE3, 0x6D, 0x50,
        0x8C, 0xE2, 0x3C, 0x38, 0x8F, 0xE3, 0x62, 0x50, 0x8C, 0xE2, 0x3C, 0x38, 0x89, 0xE3, 0xE0,
        0x50, 0x8C, 0xE2, 0xAC, 0x3F, 0x89, 0xE3, 0x42, 0x50, 0x8C, 0xE2, 0xAC, 0x3F, 0x88, 0xE3,
        0x77, 0x50, 0x8C, 0xE2, 0xAC, 0x3F, 0x8F, 0xE3, 0x6E, 0x50, 0x8C, 0xE2, 0x3C, 0x38, 0x8D,
        0xE3, 0x64, 0x50, 0x8C, 0xE2, 0x67, 0x50, 0x8D, 0xE2, 0x3F, 0x50, 0x8C, 0xE2, 0xE1, 0x20,
        0x85, 0xE3, 0x66, 0x50, 0x8C, 0xE2, 0xE1, 0x20, 0x73, 0xE2, 0x66, 0x50, 0x8C, 0xE2, 0xE1,
        0x20, 0x8E, 0xE3, 0x66, 0x50, 0x8C, 0xE2, 0x52, 0x69, 0x63, 0x68, 0x67, 0x50, 0x8C, 0xE2,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x50, 0x05, 0x00, 0x00, 0x64, 0x86, 0x07, 0x00, 0x5F, 0x41, 0xFC, 0x5E, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x22, 0x00, 0x0B, 0x02, 0x0E, 0x1A, 0x00,
        0xFC, 0x00, 0x00, 0x00, 0xD6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE4, 0x14, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xE0,
        0x68, 0x02, 0x00, 0x03, 0x00, 0x60, 0x81, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xA3, 0x01, 0x00, 0x28,
        0x00, 0x00, 0x00, 0x00, 0xF0, 0x01, 0x00, 0xE0, 0x01, 0x00, 0x00, 0x00, 0xD0, 0x01, 0x00,
        0x60, 0x0F, 0x00, 0x00, 0x00, 0xC4, 0x01, 0x00, 0xF8, 0x46, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x54, 0x06, 0x00, 0x00, 0xF0, 0x91, 0x01, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x92, 0x01, 0x00, 0x30, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x00, 0x48, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    // The assembler program used to generate this string is as follows:
    //
    // bits 64
    // default rel
    // segment .text
    // global main
    // extern ExitProcess
    // main:
    //      xor rax, rax
    //      call ExitProcess
    //
    //
    // The code can be compiled using nasm (https://nasm.us) with the command below:
    //      nasm -f win64 <filename>.asm -o <filename>.obj
    static COFF_FILE_SINGLE_STRING_IN_STRING_TABLE: [u8; 220] = [
        0x64, 0x86, 0x1, 0x0, 0xb5, 0x39, 0x91, 0x62, 0x4e, 0x0, 0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x2e, 0x74, 0x65, 0x78, 0x74, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x8, 0x0, 0x0, 0x0, 0x3c, 0x0, 0x0, 0x0, 0x44, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        0x1, 0x0, 0x0, 0x0, 0x20, 0x0, 0x50, 0x60, 0x48, 0x31, 0xc0, 0xe8, 0x0, 0x0, 0x0, 0x0, 0x4,
        0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x4, 0x0, 0x2e, 0x66, 0x69, 0x6c, 0x65, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0, 0xfe, 0xff, 0x0, 0x0, 0x67, 0x1, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67,
        0x73, 0x2e, 0x61, 0x73, 0x6d, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2e, 0x74, 0x65, 0x78,
        0x74, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x3, 0x1, 0x8, 0x0, 0x0, 0x0,
        0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2e, 0x61, 0x62,
        0x73, 0x6f, 0x6c, 0x75, 0x74, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, 0x0, 0x6d, 0x61,
        0x69, 0x6e, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x0, 0x10,
        0x0, 0x0, 0x0, 0x45, 0x78, 0x69, 0x74, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x0,
    ];

    #[test]
    fn string_table_excludes_length() {
        let coff = Coff::parse(&&COFF_FILE_SINGLE_STRING_IN_STRING_TABLE[..]).unwrap();
        let string_table = coff.strings.to_vec().unwrap();

        assert!(string_table == vec!["ExitProcess"]);
    }

    #[test]
    fn symbol_name_excludes_length() {
        let coff = Coff::parse(&COFF_FILE_SINGLE_STRING_IN_STRING_TABLE).unwrap();
        let strings = coff.strings;
        let symbols = coff
            .symbols
            .iter()
            .filter(|(_, name, _)| name.is_none())
            .map(|(_, _, sym)| sym.name(&strings).unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(symbols, vec!["ExitProcess"])
    }

    #[test]
    fn invalid_dos_header() {
        if let Ok(_) = PE::parse(&INVALID_DOS_SIGNATURE) {
            panic!("must not parse PE with invalid DOS header");
        }
    }

    #[test]
    fn invalid_pe_header() {
        if let Ok(_) = PE::parse(&INVALID_PE_SIGNATURE) {
            panic!("must not parse PE with invalid PE header");
        }
    }
}
