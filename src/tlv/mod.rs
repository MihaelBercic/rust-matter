use std::io::Cursor;

use crate::network::enums::Pet;
use crate::tlv::control::Control;
use crate::tlv::element_type::ElementType;
use crate::tlv::element_type::ElementType::{BooleanFalse, BooleanTrue, OctetString16, OctetString32, OctetString64, OctetString8, Signed16, Signed32, Signed64, Signed8, UTFString16, UTFString32, UTFString64, UTFString8, Unsigned16, Unsigned32, Unsigned64, Unsigned8};
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl;
use crate::tlv::tag_control::TagControl::Anonymous0;
use crate::tlv::tag_number::TagNumber;
use crate::tlv::tlv::TLV;

pub(crate) mod element_type;
pub mod tag_control;
pub mod encodable_value;
pub mod tag_number;
pub mod impl_encodable;
pub mod tlv;
pub mod control;
pub mod tag;
pub mod structs;

pub trait TLVRepresentable {
    fn to_tlv(&self) -> TLV;
    fn into_tlv(self) -> TLV;
}


pub fn create_tlv(element_type: ElementType) -> TLV {
    TLV {
        control: Control { tag_control: Anonymous0, element_type },
        tag: Tag {
            vendor: None,
            profile: None,
            tag_number: None,
        },
    }
}

pub fn create_advanced_tlv(element_type: ElementType, tag_control: TagControl, tag_number: Option<TagNumber>, vendor: Option<u16>, profile: Option<u16>) -> TLV {
    TLV {
        control: Control { tag_control, element_type },
        tag: Tag {
            vendor,
            profile,
            tag_number,
        },
    }
}

pub fn as_hex_string(vec: &Vec<u8>) -> String {
    vec.iter().map(|x| format!("{:02x}", x)).collect::<Vec<String>>().join(" ")
}

pub fn tlv_as_hex(element_type: ElementType) -> String {
    as_hex_string(&create_tlv(element_type).to_bytes())
}

pub fn parse_tlv(data: &[u8]) -> TLV {
    TLV::try_from_cursor(&mut Cursor::new(data)).unwrap()
}

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
unsigned_tlv!(u8, u16, u32, u64);

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
signed_tlv!(i8, i16, i32, i64);

impl From<bool> for ElementType {
    fn from(value: bool) -> Self {
        if value { BooleanTrue } else { BooleanFalse }
    }
}

impl From<String> for ElementType {
    fn from(value: String) -> ElementType {
        let data = value.to_string();
        match data.len() {
            0..0xFF => UTFString8(data),
            0xFF..0xFF_FF => UTFString16(data),
            0xFF_FF..0xFF_FF_FF_FF => UTFString32(data),
            _ => UTFString64(data)
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
            _ => OctetString64(value)
        }
    }
}

fn test() {
    let x: ElementType = 22u8.into();
}


pub fn tlv_unsigned<T: Into<u64>>(value: T) -> ElementType {
    let x: u64 = value.into();
    match x {
        0..=0xFF => Unsigned8(x as u8),
        0x100..=0xFF_FF => Unsigned16(x as u16),
        0x10000..=0xFF_FF_FF_FF => Unsigned32(x as u32),
        _ => Unsigned64(x)
    }
}

pub fn tlv_octet_string(value: &[u8]) -> ElementType {
    let data = value.to_vec();
    match data.len() {
        0..0xFF => OctetString8(data),
        0xFF..0xFF_FF => OctetString16(data),
        0xFF_FF..0xFF_FF_FF_FF => OctetString32(data),
        _ => OctetString64(data)
    }
}

pub fn tlv_string<T: ToString>(str: T) -> ElementType {
    let data = str.to_string();
    match data.len() {
        0..0xFF => UTFString8(data),
        0xFF..0xFF_FF => UTFString16(data),
        0xFF_FF..0xFF_FF_FF_FF => UTFString32(data),
        _ => UTFString64(data)
    }
}