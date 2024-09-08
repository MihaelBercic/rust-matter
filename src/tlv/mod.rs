use std::io::Cursor;

use crate::network::enums::Pet;
use crate::tlv::control::Control;
use crate::tlv::element_type::ElementType;
use crate::tlv::element_type::ElementType::{Unsigned16, Unsigned32, Unsigned64, Unsigned8};
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

pub trait TLVEncodable {
    fn to_tlv(&self) -> Vec<u8>;
    fn from_tlv(bytes: &[u8]) -> Self;
}


pub fn create_tlv(element_type: ElementType) -> TLV {
    TLV {
        control: Control { tag_control: Anonymous0, element_type: element_type.clone() },
        tag: Tag {
            vendor: None,
            profile: None,
            tag_number: None,
        },
    }
}

pub fn create_advanced_tlv(element_type: ElementType, tag_control: TagControl, tag_number: Option<TagNumber>, vendor: Option<u16>, profile: Option<u16>) -> TLV {
    TLV {
        control: Control { tag_control, element_type: element_type.clone() },
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

pub fn create_unsigned<T: Into<u64>>(value: T) -> ElementType {
    let x: u64 = value.into();
    match x {
        0..=0xFF => Unsigned8(x as u8),
        0x100..=0xFF_FF => Unsigned16(x as u16),
        0x10000..=0xFF_FF_FF_FF => Unsigned32(x as u32),
        _ => Unsigned64(x)
    }
}