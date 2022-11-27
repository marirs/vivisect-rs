#![cfg_attr(not(feature = "std"), no_std)]

pub mod analysis;
pub mod constants;
pub mod context;
pub mod emulator;
pub mod ihex;
pub mod memory;
pub mod monitor;
pub mod page_lookup;
pub mod parser;
pub mod utils;
pub mod vstruct;
pub mod workspace;

#[cfg(feature = "std")]
extern crate core;

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;

/////////////////////////
// Misc/Helper Modules
/////////////////////////

#[allow(unused)]
macro_rules! if_std {
    ($($i:item)*) => ($(
        #[cfg(feature = "std")]
        $i
    )*)
}

#[allow(unused)]
macro_rules! if_alloc {
    ($($i:item)*) => ($(
        #[cfg(feature = "alloc")]
        $i
    )*)
}

#[cfg(feature = "alloc")]
pub mod error;

pub mod strtab;

/// Binary container size information and byte-order context
pub mod container {
    pub use scroll::Endian;

    #[derive(Debug, Copy, Clone, PartialEq)]
    /// The size of a binary container
    pub enum Container {
        Little,
        Big,
    }

    impl Container {
        /// Is this a 64-bit container or not?
        pub fn is_big(self) -> bool {
            self == Container::Big
        }
    }

    #[cfg(not(target_pointer_width = "64"))]
    /// The default binary container size - either `Big` or `Little`, depending on whether the host machine's pointer size is 64 or not
    pub const CONTAINER: Container = Container::Little;

    #[cfg(target_pointer_width = "64")]
    /// The default binary container size - either `Big` or `Little`, depending on whether the host machine's pointer size is 64 or not
    pub const CONTAINER: Container = Container::Big;

    impl Default for Container {
        #[inline]
        fn default() -> Self {
            CONTAINER
        }
    }

    #[derive(Debug, Copy, Clone, PartialEq)]
    /// A binary parsing context, including the container size and underlying byte endianness
    pub struct Ctx {
        pub container: Container,
        pub le: scroll::Endian,
    }

    impl Ctx {
        /// Whether this binary container context is "big" or not
        pub fn is_big(self) -> bool {
            self.container.is_big()
        }
        /// Whether this binary container context is little endian or not
        pub fn is_little_endian(self) -> bool {
            self.le.is_little()
        }
        /// Create a new binary container context
        pub fn new(container: Container, le: scroll::Endian) -> Self {
            Ctx { container, le }
        }
        /// Return a dubious pointer/address byte size for the container
        pub fn size(self) -> usize {
            match self.container {
                // TODO: require pointer size initialization/setting or default to container size with these values, e.g., avr pointer width will be smaller iirc
                Container::Little => 4,
                Container::Big => 8,
            }
        }
    }

    impl From<Container> for Ctx {
        fn from(container: Container) -> Self {
            Ctx {
                container,
                le: scroll::Endian::default(),
            }
        }
    }

    impl From<scroll::Endian> for Ctx {
        fn from(le: scroll::Endian) -> Self {
            Ctx {
                container: CONTAINER,
                le,
            }
        }
    }

    impl Default for Ctx {
        #[inline]
        fn default() -> Self {
            Ctx {
                container: Container::default(),
                le: scroll::Endian::default(),
            }
        }
    }
}

macro_rules! if_everything {
    ($($i:item)*) => ($(
        #[cfg(all(feature = "endian_fd", feature = "elf64", feature = "elf32", feature = "pe64", feature = "pe32", feature = "mach64", feature = "mach32", feature = "archive"))]
        $i
    )*)
}

if_everything! {

    #[derive(Debug, Default)]
    /// Information obtained from a peek `Hint`
    pub struct HintData {
        pub is_lsb: bool,
        pub is_64: Option<bool>,
    }

    #[derive(Debug)]
    /// A hint at the underlying binary format for 16 bytes of arbitrary data
    pub enum Hint {
        Elf(HintData),
        Mach(HintData),
        MachFat(usize),
        PE,
        Archive,
        Unknown(u64),
    }

    /// Peeks at `bytes`, and returns a `Hint`
    pub fn peek_bytes(bytes: &[u8; 16]) -> error::Result<Hint> {
        use scroll::{Pread, LE, BE};
        use crate::mach::{fat, header};
        if &bytes[0..elf::header::SELFMAG] == elf::header::ELFMAG {
            let class = bytes[elf::header::EI_CLASS];
            let is_lsb = bytes[elf::header::EI_DATA] == elf::header::ELFDATA2LSB;
            let is_64 =
                if class == elf::header::ELFCLASS64 {
                    Some (true)
                } else if class == elf::header::ELFCLASS32 {
                    Some (false)
                } else { None };

            Ok(Hint::Elf(HintData { is_lsb, is_64 }))
        } else if &bytes[0..archive::SIZEOF_MAGIC] == archive::MAGIC {
            Ok(Hint::Archive)
        } else if (&bytes[0..2]).pread_with::<u16>(0, LE)? == pe::header::DOS_MAGIC {
            Ok(Hint::PE)
        } else {
            let (magic, maybe_ctx) = mach::parse_magic_and_ctx(bytes, 0)?;
            match magic {
                fat::FAT_MAGIC => {
                    // should probably verify this is always Big Endian...
                    let narchitectures = bytes.pread_with::<u32>(4, BE)? as usize;
                    Ok(Hint::MachFat(narchitectures))
                },
                header::MH_CIGAM_64 | header::MH_CIGAM | header::MH_MAGIC_64 | header::MH_MAGIC => {
                    if let Some(ctx) = maybe_ctx {
                        Ok(Hint::Mach(HintData { is_lsb: ctx.le.is_little(), is_64: Some(ctx.container.is_big()) }))
                    } else {
                        Err(error::Error::Malformed(format!("Correct mach magic {:#x} does not have a matching parsing context!", magic)))
                    }
                },
                // its something else
                _ => Ok(Hint::Unknown(bytes.pread::<u64>(0)?))
            }
        }
    }

    /// Peeks at the underlying Read object. Requires the underlying bytes to have at least 16 byte length. Resets the seek to `Start` after reading.
    #[cfg(feature = "std")]
    pub fn peek<R: ::std::io::Read + ::std::io::Seek>(fd: &mut R) -> error::Result<Hint> {
        use std::io::SeekFrom;
        let mut bytes = [0u8; 16];
        fd.seek(SeekFrom::Start(0))?;
        fd.read_exact(&mut bytes)?;
        fd.seek(SeekFrom::Start(0))?;
        peek_bytes(&bytes)
    }

    /// Takes a reference to the first 16 bytes of the total bytes slice and convert it to an array for `peek_bytes` to use.
    /// Returns None if bytes's length is less than 16.
    fn take_hint_bytes(bytes: &[u8]) -> Option<&[u8; 16]> {
        use core::convert::TryInto;
        bytes.get(0..16)
            .and_then(|hint_bytes_slice| {
                hint_bytes_slice.try_into().ok()
            })
    }

    #[derive(Debug, Clone)]
    #[allow(clippy::large_enum_variant)]
    /// A parseable object that we understands
    pub enum Object<'a> {
        /// An ELF32/ELF64!
        Elf(elf::Elf<'a>),
        /// A PE32/PE32+!
        PE(pe::PE<'a>),
        /// A 32/64-bit Mach-o binary _OR_ it is a multi-architecture binary container!
        Mach(mach::Mach<'a>),
        /// A Unix archive
        Archive(archive::Archive<'a>),
        /// None of the above, with the given magic value
        Unknown(u64),
    }

    impl<'a> Object<'a> {
        /// Tries to parse an `Object` from `bytes`
        pub fn parse(bytes: &[u8]) -> error::Result<Object> {
            if let Some(hint_bytes) = take_hint_bytes(bytes) {
                match peek_bytes(hint_bytes)? {
                    Hint::Elf(_) => Ok(Object::Elf(elf::Elf::parse(bytes)?)),
                    Hint::Mach(_) | Hint::MachFat(_) => Ok(Object::Mach(mach::Mach::parse(bytes)?)),
                    Hint::Archive => Ok(Object::Archive(archive::Archive::parse(bytes)?)),
                    Hint::PE => Ok(Object::PE(pe::PE::parse(bytes)?)),
                    Hint::Unknown(magic) => Ok(Object::Unknown(magic))
                }
            } else {
                Err(error::Error::Malformed(format!("Object is too small.")))
            }
        }
    }
} // end if_endian_fd

/////////////////////////
// Binary Modules
/////////////////////////

#[cfg(any(feature = "elf64", feature = "elf32"))]
#[macro_use]
pub mod elf;

#[cfg(feature = "elf32")]
/// The ELF 32-bit struct definitions and associated values, re-exported for easy "type-punning"
pub mod elf32 {
    pub use crate::elf::dynamic::dyn32 as dynamic;
    pub use crate::elf::header::header32 as header;
    pub use crate::elf::note::Nhdr32 as Note;
    pub use crate::elf::program_header::program_header32 as program_header;
    pub use crate::elf::reloc::reloc32 as reloc;
    pub use crate::elf::section_header::section_header32 as section_header;
    pub use crate::elf::sym::sym32 as sym;

    pub mod gnu_hash {
        pub use crate::elf::gnu_hash::hash;
        elf_gnu_hash_impl!(u32);
    }
}

#[cfg(feature = "elf64")]
/// The ELF 64-bit struct definitions and associated values, re-exported for easy "type-punning"
pub mod elf64 {
    pub use crate::elf::dynamic::dyn64 as dynamic;
    pub use crate::elf::header::header64 as header;
    pub use crate::elf::note::Nhdr64 as Note;
    pub use crate::elf::program_header::program_header64 as program_header;
    pub use crate::elf::reloc::reloc64 as reloc;
    pub use crate::elf::section_header::section_header64 as section_header;
    pub use crate::elf::sym::sym64 as sym;

    pub mod gnu_hash {
        pub use crate::elf::gnu_hash::hash;
        elf_gnu_hash_impl!(u64);
    }
}

#[cfg(any(feature = "mach32", feature = "mach64"))]
pub mod mach;

#[cfg(any(feature = "pe32", feature = "pe64"))]
pub mod pe;

#[cfg(feature = "archive")]
pub mod archive;

#[cfg(test)]
mod tests {
    use super::*;
    if_everything! {
        #[test]
        fn take_hint_bytes_long_enough() {
            let bytes_array = [1; 32];
            let bytes = &bytes_array[..];
            assert!(take_hint_bytes(bytes).is_some())
        }

        #[test]
        fn take_hint_bytes_not_long_enough() {
            let bytes_array = [1; 8];
            let bytes = &bytes_array[..];
            assert!(take_hint_bytes(bytes).is_none())
        }
    }
}
