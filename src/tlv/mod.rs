use std::io::Cursor;

use crate::network::enums::Pet;
use crate::tlv::control::Control;
use crate::tlv::element_type::ElementType;
use crate::tlv::element_type::ElementType::*;
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl;
use crate::tlv::tag_control::TagControl::Anonymous0;
use crate::tlv::tag_number::TagNumber;
use crate::tlv::tlv::TLV;

pub mod control;
pub(crate) mod element_type;
pub mod encodable_value;
pub mod impl_encodable;
pub mod structs;
pub mod tag;
pub mod tag_control;
pub mod tag_number;
pub mod tlv;

macro_rules! unsigned_tlv {
    ($($t:ty),*) => {
        $(
        impl From<$t> for ElementType {
            fn from(value: $t) -> Self {
                let x = value as u64;
                match x {
                    0..=0xFF => Unsigned8(x as u8),
                    0x100..=0xFF_FF => Unsigned16(x as u16),
                    0x10000..=0xFF_FF_FF_FF => Unsigned32(x as u32),
                    _ => Unsigned64(x as u64)
                }
            }
        }
        )*
    };
}

macro_rules! signed_tlv {
    ($($t:ty),*) => {
        $(
        impl From<$t> for ElementType {
            fn from(value: $t) -> Self {
                let x = value as i64;
                match x {
                    -0x80..=0x7F => Signed8(x as i8),
                    -0x80_00..=0x7F_FF => Signed16(x as i16),
                    -0x80_00_00_00..=0x7F_FF_FF_FF => Signed32(x as i32),
                    _ => Signed64(x as i64)
                }
            }
        }
        )*
    };
}

unsigned_tlv!(u8, u16, u32, u64);
signed_tlv!(i8, i16, i32, i64);

impl From<bool> for ElementType {
    fn from(value: bool) -> Self {
        if value {
            BooleanTrue
        } else {
            BooleanFalse
        }
    }
}

impl From<String> for ElementType {
    fn from(value: String) -> ElementType {
        let data = value.to_string();
        match data.len() {
            0..0xFF => UTFString8(data),
            0xFF..0xFF_FF => UTFString16(data),
            0xFF_FF..0xFF_FF_FF_FF => UTFString32(data),
            _ => UTFString64(data),
        }
    }
}

impl From<Vec<u8>> for ElementType {
    fn from(value: Vec<u8>) -> Self {
        let len = value.len() as u64;
        match len {
            0..=0xFF => OctetString8(value),
            0x100..=0xFF_FF => OctetString16(value),
            0x10000..=0xFF_FF_FF_FF => OctetString32(value),
            _ => OctetString64(value),
        }
    }
}

impl<const C: usize> From<[u8; C]> for ElementType {
    fn from(value: [u8; C]) -> Self {
        let len = C as u64;
        match len {
            0..=0xFF => OctetString8(value.into()),
            0x100..=0xFF_FF => OctetString16(value.into()),
            0x10000..=0xFF_FF_FF_FF => OctetString32(value.into()),
            _ => OctetString64(value.into()),
        }
    }
}

enum Test<const C: usize> {
    A([u8; C]),
    B([u8; C]),
}

fn test() {
    Test::A([1, 2, 3]);
    Test::A([1, 2, 3, 5]);
    Test::B([1, 2, 3, 5]);
}

pub fn tlv_unsigned<T: Into<u64>>(value: T) -> ElementType {
    let x: u64 = value.into();
    match x {
        0..=0xFF => Unsigned8(x as u8),
        0x100..=0xFF_FF => Unsigned16(x as u16),
        0x10000..=0xFF_FF_FF_FF => Unsigned32(x as u32),
        _ => Unsigned64(x),
    }
}

pub fn tlv_octet_string(value: &[u8]) -> ElementType {
    let data = value.to_vec();
    match data.len() {
        0..0xFF => OctetString8(data),
        0xFF..0xFF_FF => OctetString16(data),
        0xFF_FF..0xFF_FF_FF_FF => OctetString32(data),
        _ => OctetString64(data),
    }
}

pub fn tlv_string<T: ToString>(str: T) -> ElementType {
    let data = str.to_string();
    match data.len() {
        0..0xFF => UTFString8(data),
        0xFF..0xFF_FF => UTFString16(data),
        0xFF_FF..0xFF_FF_FF_FF => UTFString32(data),
        _ => UTFString64(data),
    }
}
