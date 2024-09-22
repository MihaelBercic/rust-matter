use crate::tlv::tag_control::TagControl::*;

///
/// @author Mihael Berčič
/// @date 1. 8. 24
///
#[repr(u8)]
#[derive(Clone, Debug)]
pub enum TagControl {
    Anonymous0 = 0,
    ContextSpecific8 = 1,
    CommonProfile16 = 2,
    CommonProfile32 = 3,
    ImplicitProfile16 = 4,
    ImplicitProfile32 = 5,
    FullyQualified48 = 6,
    FullyQualified64 = 7,
}

impl From<u8> for TagControl {
    fn from(value: u8) -> Self {
        match value {
            1 => ContextSpecific8,
            2 => CommonProfile16,
            3 => CommonProfile32,
            4 => ImplicitProfile16,
            5 => ImplicitProfile32,
            6 => FullyQualified48,
            7 => FullyQualified64,
            _ => Anonymous0,
        }
    }
}