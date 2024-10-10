use crate::envi::constants::{ARCH_NAMES, ARCH_NAMES_REV};
use crate::envi::ArchitectureModule;
use crate::envi::Result;
use crate::error::Error::InvalidState;
use lazy_static::lazy_static;
use std::rc::Rc;

// """
// A file full of bit twidling helpers
// """
//
// import struct
//
// MAX_WORD = 32  # usually no more than 8, 16 is for SIMD register support
//
// # Masks to use for unsigned anding to size
// u_maxes = [(2 ** (8*i)) - 1 for i in range(MAX_WORD+1)]
// u_maxes[0] = 0  # powers of 0 are 1, but we need 0
// bu_maxes = [(2 ** (i)) - 1 for i in range(8*MAX_WORD+1)]
//
// # Masks of just the sign bit for different sizes
// sign_bits = [(2 ** (8*i)) >> 1 for i in range(MAX_WORD+1)]
// sign_bits[0] = 0  # powers of 0 are 1, but we need 0
// bsign_bits = [(2 ** i) >> 1 for i in range(8*MAX_WORD+1)]
//
// # Max *signed* masks (all but top bit )
// s_maxes = [u_maxes[i] ^ sign_bits[i] for i in range(len(u_maxes))]
// s_maxes[0] = 0
//
// # bit width masks
// b_masks = [(2**i)-1 for i in range(MAX_WORD*8)]
// b_masks[0] = 0
//
// def unsigned(value, size):
//     """
//     Make a value unsigned based on it's size.
//     """
//     return value & u_maxes[size]
//
// def signed(value, size):
//     """
//     Make a value signed based on it's size.
//     """
//     x = unsigned(value, size)
//     if x & sign_bits[size]:
//         x = (x - u_maxes[size]) - 1
//     return x
//
// def bsigned(value, size):
//     """
//     Make a value signed based on it's size.
//     """
//     if value & bsign_bits[size]:
//         value = (value - bu_maxes[size]) - 1
//     return value
//
// def is_signed(value, size):
//     x = unsigned(value, size)
//     return bool(x & sign_bits[size])
//
// def sign_extend(value, cursize, newsize):
//     """
//     Take a value and extend it's size filling
//     in the space with the value of the high
//     order bit.
//     """
//     x = unsigned(value, cursize)
//     if cursize != newsize:
//         # Test for signed w/o the call
//         if x & sign_bits[cursize]:
//             delta = newsize - cursize
//             highbits = u_maxes[delta]
//             x |= highbits << (8*cursize)
//     return x
//
// def bsign_extend(value, cursize, newsize):
//     x = value
//     if cursize != newsize:
//         if x & bsign_bits[cursize]:
//             delta = newsize - cursize
//             highbits = bu_maxes[delta]
//             x |= highbits << (cursize)
//     return x
//
// def is_parity(val):
//     s = 0
//     while val:
//         s ^= val & 1
//         val = val >> 1
//     return (not s)
//
// parity_table = []
// for i in range(256):
//     parity_table.append(is_parity(i))
//
// def is_parity_byte(bval):
//     """
//     An "optimized" parity checker that looks up the index.
//     """
//     return parity_table[bval & 0xff]
//
// def lsb(value):
//     return value & 0x1
//
// def msb(value, size):
//     return bool(value & sign_bits[size])
//
// def msb_minus_one(value, size):
//     bsize = size << 3
//     return bool(value & bsign_bits[bsize-1])
//
// def is_signed_half_carry(value, size, src):
//     '''
//     BCD carry/borrow in the second most important nibble:
//         32bit   - bit 27
//         16bit   - bit 11
//         8bit    - bit 3
//     '''
//     bitsize = (size << 3) - 5
//     mask = 1<<bitsize
//
//     p1 = value & mask
//     p2 = src & mask
//
//     return ((p1 ^ p2) != 0)
//
// def is_signed_carry(value, size, src):
//     smax = s_maxes[size]
//     if value > smax > src:
//         return True
//     if value < -smax < -src:
//         return True
//     return False
//
// def is_signed_overflow(value, size):
//     smax = s_maxes[size]
//     if value > smax:
//         return True
//     if value < -smax:
//         return True
//     return False
//
// def is_unsigned_carry(value, size):
//     umax = u_maxes[size]
//     if value > umax:
//         return True
//     elif value < 0:
//         return True
//     return False
//
// def is_aux_carry(src, dst):
//     return (dst & 0xf) + (src & 0xf) > 15
//
// def is_aux_carry_sub(src, dst):
//     return src & 0xf > dst & 0xf
//
// # set of format lists which make size, endianness, and signedness fast and easy
// le_fmt_chars = (None, "B", "<H", None, "<I", None, None, None, "<Q")
// be_fmt_chars = (None, "B", ">H", None, ">I", None, None, None, ">Q")
// fmt_chars = (le_fmt_chars, be_fmt_chars)
//
// le_fmt_schars = (None,"b","<h",None,"<i",None,None,None,"<q")
// be_fmt_schars = (None,"b",">h",None,">i",None,None,None,">q")
// fmt_schars = (le_fmt_schars, be_fmt_schars)
//
// master_fmts = (fmt_chars, fmt_schars)
//
// fmt_sizes =  (None,1,2,4,4,8,8,8,8)
//
// le_fmt_float = (None, None, None, None, '<f', None, None, None, '<d')
// be_fmt_float = (None, None, None, None, '>f', None, None, None, '>d')
//
// fmt_floats = (le_fmt_float, be_fmt_float)
//
//
// def getFormat(size, big_endian=False, signed=False):
//     '''
//     Returns the proper struct format for numbers up to 8 bytes in length
//     Endianness and Signedness aware.
//
//     Only useful for *full individual* numbers... ie. 1, 2, 4, 8.  Numbers
//     of 24-bits (3), 40-bit (5), 48-bits (6) or 56-bits (7) are not accounted
//     for here and will return None.
//     '''
//     return master_fmts[signed][big_endian][size]
//
// def getFloatFormat(size, big_endian=False):
//     '''
//     Returns the proper struct format for numbers up to 8 bytes in length
//     Endianness and Signedness aware.
//
//     Only useful for *full individual* numbers... ie. 1, 2, 4, 8.  Numbers
//     of 24-bits (3), 40-bit (5), 48-bits (6) or 56-bits (7) are not accounted
//     for here and will return None.
//     '''
//     return fmt_floats[big_endian][size]
//
// def parsebytes(bytes, offset, size, sign=False, bigend=False):
//     """
//     Mostly for pulling immediates out of strings...
//     """
//     if size > 8:
//         return slowparsebytes(bytes, offset, size, sign=sign, bigend=bigend)
//     if bigend:
//         f = be_fmt_chars[size]
//     else:
//         f = le_fmt_chars[size]
//     if f is None:
//         return slowparsebytes(bytes, offset, size, sign=sign, bigend=bigend)
//     d = bytes[offset:offset+size]
//     x = struct.unpack(f, d)[0]
//     if sign:
//         x = signed(x, size)
//     return x
//
// def slowparsebytes(bytes, offset, size, sign=False, bigend=False):
//     if bigend:
//         begin = offset
//         inc = 1
//     else:
//         begin = offset + (size-1)
//         inc = -1
//
//     ret = 0
//     ioff = 0
//     for x in range(size):
//         ret = ret << 8
//         ret |= bytes[begin+ioff]
//         ioff += inc
//     if sign:
//         ret = signed(ret, size)
//     return ret
//
// def buildbytes(value, size, bigend=False):
//     value = unsigned(value, size)
//     if bigend:
//         f = be_fmt_chars[size]
//     else:
//         f = le_fmt_chars[size]
//     if f is None:
//         raise Exception("envi.bits.buildbytes needs slowbuildbytes")
//     return struct.pack(f, value)
//
// def byteswap(value, size):
//     ret = 0
//     for i in range(size):
//         ret = ret << 8
//         ret |= (value >> (8*i)) & 0xff
//     return ret
//
// hex_fmt = {
//     0:'0x%.1x',
//     1:"0x%.2x",
//     2:"0x%.4x",
//     4:"0x%.8x",
//     8:"0x%.16x",
// }
//
// def intwidth(val):
//     if val < 0:
//         val = abs(val)
//     ret = 0
//     while val:
//         ret += 1
//         val = val >> 8
//     return ret
//
// def hex(value, size=None):
//     if size is None:
//         size = intwidth(value)
//
//     fmt = hex_fmt.get(size)
//     if fmt is not None:
//         return fmt % value
//
//     x = []
//     while value:
//         x.append('%.2x' % (value & 0xff))
//         value = value >> 8
//     x.reverse()
//     return '0x%.s' % ''.join(x)
//
//
//     return hex_fmt.get(size) % value
//
// def binrepr(intval, bitwidth=None):
//     '''
//     Return a string of one's and zero's for the given value.
//     '''
//     ret = []
//     while intval:
//         ret.append(str(intval & 0x1))
//         intval >>= 1
//     ret.reverse()
//     binstr = ''.join(ret)
//     if bitwidth is not None:
//         binstr = binstr.rjust(bitwidth, '0')
//     return binstr
//
// def binary(binstr):
//     '''
//     Decode a binary string of 1/0's into a python number
//     '''
//     return int(binstr, 2)
//
// def binbytes(binstr):
//     '''
//     Decode a binary string of 1/0's into a python binary
//     string.
//     '''
//     if len(binstr) % 8 != 0:
//         raise Exception('Byte padded binary strings only for now!')
//     bytez = ''
//     while binstr:
//         bytez += chr(binary(binstr[:8]))
//         binstr = binstr[8:]
//     return bytez
//
// def parsebits(bytes, offset, bitoff, bitsize):
//     '''
//     Parse bitsize bits from the bit offset bitoff beginning
//     at offset bytes.
//
//     Example:
//     '''
//     val = 0
//     cnt = 0
//     while cnt < bitsize:
//
//         addbit = bitoff + cnt
//         addoff = offset + (addbit >> 3)
//
//         modoff = addbit % 8
//
//         o = bytes[addoff]
//         val = (val << 1) + ((o >> (7 - modoff)) & 1)
//
//         cnt += 1
//
//     return val
//
// def masktest(s):
//     '''
//     Specify a bit mask with the following syntax:
//     '110100xxx00xx' to return a tester callback which will
//     determine if an integer value meets the mask.
//
//     example:
//         opcode = 0x4388e234
//         if masktest('1011xxxx0000')(opcode):
//             print('MATCHED!')
//
//     NOTE: For performance reasons, it is recommeneded that
//     masktest be used to initialize a static list of tests
//     that are re-used rather than reconstructed.
//     '''
//     maskin = binary(s.replace('0', '1').replace('x', '0'))
//     matchval = binary(s.replace('x', '0'))
//
//     def domask(testval):
//         return testval & maskin == matchval
//     return domask
//
// def align(origsize, alignment):
//     '''
//     Returns an aligned size based on alignment argument
//     '''
//     remainder = origsize % alignment
//     if remainder == 0:
//         return origsize
//     else:
//         return origsize + (alignment - remainder)

pub const MAX_WORD: i32 = 32;

lazy_static! {
    static ref U_MAXES: Vec<i32> = {
        let mut u_maxes: Vec<i32> = (0..MAX_WORD + 1)
            .map(|i| (2i32.pow(8 * i as u32) - 1))
            .collect();
        u_maxes[0] = 0;
        u_maxes
    };
    static ref BU_MAXES: Vec<i32> = (0..8 * MAX_WORD + 1)
        .map(|i| 2i32.pow(i as u32) - 1)
        .collect();
    static ref SIGN_BITS: Vec<i32> = {
        let mut sign_bits: Vec<i32> = (0..MAX_WORD + 1)
            .map(|i| 2i32.pow(8 * i as u32) >> 1)
            .collect();
        sign_bits[0] = 0;
        sign_bits
    };
    static ref B_SIGN_BITS: Vec<i32> = (0..8 * MAX_WORD + 1)
        .map(|i| 2i32.pow(i as u32) >> 1)
        .collect();
    static ref S_MAXES: Vec<i32> = {
        let mut s_maxes: Vec<i32> = (0..MAX_WORD + 1)
            .map(|i| U_MAXES[i as usize] ^ SIGN_BITS[i as usize])
            .collect();
        s_maxes[0] = 0;
        s_maxes
    };
    static ref B_MASKS: Vec<i32> = {
        let mut b_masks: Vec<i32> = (0..MAX_WORD * 8).map(|i| 2i32.pow(i as u32) - 1).collect();
        b_masks[0] = 0;
        b_masks
    };
    static ref PARITY_TABLE: Vec<bool> = (0..256).map(|i| is_parity(i)).collect();
    static ref LE_FMT_CHARS: Vec<Option<&'static str>> = vec![
        None,
        Some("B"),
        Some("<H"),
        None,
        Some("<I"),
        None,
        None,
        None,
        Some("<Q")
    ];
    static ref BE_FMT_CHARS: Vec<Option<&'static str>> = vec![
        None,
        Some("B"),
        Some(">H"),
        None,
        Some(">I"),
        None,
        None,
        None,
        Some(">Q")
    ];
    static ref FMT_CHARS: Vec<Vec<Option<&'static str>>> =
        vec![LE_FMT_CHARS.clone(), BE_FMT_CHARS.clone()];
    static ref LE_FMT_SCHARS: Vec<Option<&'static str>> = vec![
        None,
        Some("b"),
        Some("<h"),
        None,
        Some("<i"),
        None,
        None,
        None,
        Some("<q")
    ];
    static ref BE_FMT_SCHARS: Vec<Option<&'static str>> = vec![
        None,
        Some("b"),
        Some(">h"),
        None,
        Some(">i"),
        None,
        None,
        None,
        Some(">q")
    ];
    static ref FMT_SCHARS: Vec<Vec<Option<&'static str>>> =
        vec![LE_FMT_SCHARS.clone(), BE_FMT_SCHARS.clone()];
    static ref MASTER_FMTS: Vec<Vec<Vec<Option<&'static str>>>> =
        vec![FMT_CHARS.clone(), FMT_SCHARS.clone()];
    static ref FMT_SIZES: Vec<Option<i32>> = vec![
        None,
        Some(1),
        Some(2),
        Some(4),
        Some(4),
        Some(8),
        Some(8),
        Some(8),
        Some(8)
    ];
    static ref LE_FMT_FLOAT: Vec<Option<&'static str>> = vec![
        None,
        None,
        None,
        None,
        Some("<f"),
        None,
        None,
        None,
        Some("<d")
    ];
    static ref BE_FMT_FLOAT: Vec<Option<&'static str>> = vec![
        None,
        None,
        None,
        None,
        Some(">f"),
        None,
        None,
        None,
        Some(">d")
    ];
    static ref FMT_FLOATS: Vec<Vec<Option<&'static str>>> =
        vec![LE_FMT_FLOAT.clone(), BE_FMT_FLOAT.clone()];
};

pub fn signed(value: i32, size: i32) -> i32 {
    let x = unsigned(value, size);
    if x & SIGN_BITS[size as usize] != 0 {
        x - U_MAXES[size as usize] - 1
    } else {
        x
    }
}

pub fn unsigned(value: i32, size: i32) -> i32 {
    value & U_MAXES[size as usize]
}

pub fn b_signed(value: i32, size: i32) -> i32 {
    if value & B_SIGN_BITS[size as usize] != 0 {
        value - BU_MAXES[size as usize] - 1
    } else {
        value
    }
}

pub fn is_signed(value: i32, size: i32) -> bool {
    let x = unsigned(value, size);
    x & SIGN_BITS[size as usize] != 0
}

pub fn sign_extend(value: i32, cursize: i32, newsize: i32) -> i32 {
    let mut x = unsigned(value, cursize);
    if cursize != newsize && x & SIGN_BITS[cursize as usize] != 0 {
        let delta = newsize - cursize;
        let highbits = U_MAXES[delta as usize];
        x |= highbits << (8 * cursize);
    }
    x
}

pub fn bsign_extend(value: i32, cursize: i32, newsize: i32) -> i32 {
    let mut x = value;
    if cursize != newsize && x & B_SIGN_BITS[cursize as usize] != 0 {
        let delta = newsize - cursize;
        let highbits = BU_MAXES[delta as usize];
        x |= highbits << cursize;
    }
    x
}

pub fn is_parity(val: i32) -> bool {
    let mut s = 0;
    let mut val = val;
    while val != 0 {
        s ^= val & 1;
        val >>= 1;
    }
    s == 0
}

pub fn lsb(value: i32) -> i32 {
    value & 0x1
}

pub fn msb(value: i32, size: i32) -> bool {
    value & SIGN_BITS[size as usize] != 0
}

pub fn msb_minus_one(value: i32, size: i32) -> bool {
    let bsize = size << 3;
    value & B_SIGN_BITS[bsize as usize] != 0
}

pub fn is_signed_half_carry(value: i32, size: i32, src: i32) -> bool {
    let bitsize = (size << 3) - 5;
    let mask = 1 << bitsize;

    let p1 = value & mask;
    let p2 = src & mask;

    (p1 ^ p2) != 0
}

pub fn is_signed_carry(value: i32, size: i32, src: i32) -> bool {
    let smax = S_MAXES[size as usize];
    if value > smax && smax > src {
        true
    } else if value < -smax && -smax < -src {
        true
    } else {
        false
    }
}

/// Get the architecture constant by the human name.
pub fn get_arch_by_name(arch_name: &str) -> Option<i32> {
    ARCH_NAMES_REV.get(arch_name).cloned()
}

/// Get the architecture name by the constant.
pub fn get_arch_by_id(arch_id: i32) -> Option<&'static str> {
    ARCH_NAMES.get(&arch_id).cloned()
}

pub fn get_current_arch() -> Option<&'static str> {
    None
}

pub fn get_arch_modules(arch: Option<i32>) -> Vec<Rc<dyn ArchitectureModule>> {
    vec![]
}

/// Returns an aligned size based on alignment argument
pub fn align(val: i32, align: i32) -> i32 {
    let remainder = val % align;
    if remainder == 0 {
        val
    } else {
        val + (align - remainder)
    }
}

/// Return a list of (offset, size) tuples showing any memory
/// differences between the given bytes.
pub fn mem_diff(mem1: Vec<u8>, mem2: Vec<u8>) -> Result<Vec<(i32, i32)>> {
    // Quick/Optimized case...
    if mem1 == mem2 {
        return Ok(Vec::new());
    }
    let size = mem1.len();
    if size != mem2.len() {
        return Err(InvalidState(
            "mem_diff *requires* same size bytes.".to_string(),
        ));
    }
    let mut diffs = Vec::new();
    let mut offset = 0;
    while offset < size {
        if mem1[offset] != mem2[offset] {
            let begin_offset = offset;
            // Gather all the different bytes
            while offset < size && mem1[offset] != mem2[offset] {
                offset += 1;
            }
            diffs.push((begin_offset as i32, (offset - begin_offset) as i32));
        }
        offset += 1;
    }
    Ok(diffs)
}

/// Parse bitsize bits from the bit offset bitoff beginning
/// at offset bytes.
pub fn parse_bits(bytes: Vec<u8>, offset: i32, bit_off: i32, bit_size: i32) -> u8 {
    let mut val = 0;
    let mut cnt = 0;
    while cnt < bit_size {
        let add_bit = bit_off + cnt;
        let add_off = offset + (add_bit >> 3);
        let mod_off = add_bit % 8;

        let o = bytes[add_off as usize];
        val = (val << 1) + ((o >> (7 - mod_off)) & 1);
        cnt += 1;
    }
    val
}

/// Mostly for pulling immediates out of strings...
pub fn parse_bytes(
    bytes: Vec<i32>,
    offset: i32,
    size: i32,
    sign: Option<bool>,
    bigend: Option<bool>,
) -> Vec<i32> {
    let sign = sign.unwrap_or_default();
    let bigend = bigend.unwrap_or_default();
    if size > 8 {
        return slow_parse_bytes(bytes, offset, size, Some(sign), Some(bigend));
    }
    let f = if bigend {
        LE_FMT_CHARS[size as usize]
    } else {
        BE_FMT_CHARS[size as usize]
    };
    if f.is_none() {
        return slow_parse_bytes(bytes, offset, size, Some(sign), Some(bigend));
    }
    let d = &bytes[offset as usize..(offset + size) as usize];
    let x = match f.unwrap() {
        "B" => vec![d[0]],
        "H" => d.chunks(2).map(|c| c[0] | (c[1] << 8)).collect(),
        "I" => d
            .chunks(4)
            .map(|c| c[0] | (c[1] << 8) | (c[2] << 16) | (c[3] << 24))
            .collect(),
        //"Q" => d.chunks(8).map(|c| c[0] | (c[1] << 8) | (c[2] << 16) | (c[3] << 24) | (c[4] << 32) | (c[5] << 40) | (c[6] << 48) | (c[7] << 56)).collect(),
        _ => return slow_parse_bytes(bytes, offset, size, Some(sign), Some(bigend)),
    };
    if sign {
        x.iter().map(|v| signed(*v, size)).collect()
    } else {
        x
    }
}

pub fn slow_parse_bytes(
    bytes: Vec<i32>,
    offset: i32,
    size: i32,
    sign: Option<bool>,
    bigend: Option<bool>,
) -> Vec<i32> {
    let sign = sign.unwrap_or_default();
    let bigend = bigend.unwrap_or_default();
    let (begin, inc) = if bigend {
        (offset, 1)
    } else {
        (offset + size - 1, -1)
    };
    let mut ret = 0;
    let mut ioff = 0;
    let mut x = Vec::new();
    for _ in 0..size {
        ret = ret << 8;
        ret |= bytes[(begin + ioff) as usize] as i32;
        ioff += inc;
    }
    if sign {
        x.push(signed(ret, size));
    } else {
        x.push(ret);
    }
    x
}
