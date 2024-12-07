use std::io::Cursor;

use crate::tlv::control::Control;
use crate::tlv::element_type::ElementType;
use crate::tlv::element_type::ElementType::*;
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl;
use crate::tlv::tag_control::TagControl::Anonymous0;
use crate::tlv::tag_number::TagNumber;
use crate::tlv::tlv::Tlv;

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
