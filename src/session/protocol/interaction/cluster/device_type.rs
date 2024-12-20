use crate::tlv::element_type::ElementType;
use crate::tlv::element_type::ElementType::*;
use crate::tlv::{tag::Tag, tag_control::TagControl, tag_number::TagNumber::*, tlv::Tlv};

#[derive(Copy, Clone)]
pub struct DeviceType {
    pub id: u16,
    pub revision: u16,
}

impl Default for DeviceType {
    fn default() -> Self {
        Self {
            id: 0x0100, // Light
            revision: 1,
        }
    }
}

impl From<DeviceType> for ElementType {
    fn from(value: DeviceType) -> Self {
        Structure(vec![
            Tlv::new(value.id.into(), TagControl::ContextSpecific8, Tag::short(0)),
            Tlv::new(value.revision.into(), TagControl::ContextSpecific8, Tag::short(1)),
        ])
    }
}

impl From<Vec<DeviceType>> for ElementType {
    fn from(value: Vec<DeviceType>) -> Self {
        Array(value.into_iter().map(|x| Tlv::simple(x.into())).collect())
    }
}
