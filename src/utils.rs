#![allow(dead_code, unused)]

pub fn parse_bytes(bytes: Option<Vec<u8>>, offset: i32, size: i32, sign: bool, endianness: i32) -> Option<i32> {
    if size > 8{
        return slow_parse_bytes(bytes, offset, size, sign, endianness);
    }
    // if BIGEN
    None
}

pub fn slow_parse_bytes(bytes: Option<Vec<u8>>, offset: i32, size: i32, sign: bool, endianness: i32) -> Option<i32> {
    None
}

pub fn align(orig_size: usize, alignment: usize) -> usize{
    let remainder = orig_size % alignment;
    return if remainder == 0 {
        orig_size
    } else {
        orig_size + (alignment - remainder)
    }
}

pub fn guess_format_filename(filename: &str) -> String {
    String::new()
}

pub fn guess_format(bytes: Vec<u8>) -> String{
    if bytes.starts_with(b"VIV") {
        return "viv".to_string();
    }
    if bytes.ends_with(b"MSGVIV") {
        return "mpviv".to_string();
    }
    if bytes.starts_with(b"MZ") {
        return "pe".to_string();
    }
    if bytes.starts_with(b"\x7fELF") {
        return "elf".to_string();
    }
    if bytes.starts_with(b"b\x7CGC") {
        return "cgc".to_string();
    }
    "blob".to_string()
}