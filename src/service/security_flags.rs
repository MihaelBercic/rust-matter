use crate::discovery::mdns::structs::BitSubset;
use crate::service::enums::MatterSessionType;
use crate::service::enums::MatterSessionType::{Group, ReservedForFuture, Unicast};

#[derive(Debug)]
pub struct MatterSecurityFlags {
    pub(crate) flags: u8,
}

impl MatterSecurityFlags {
    pub fn is_encoded_with_privacy(&self) -> bool {
        self.flags.bit_subset(7, 1) == 1
    }

    pub fn is_control_message(&self) -> bool {
        self.flags.bit_subset(6, 1) == 1
    }

    pub fn has_message_extensions(&self) -> bool {
        self.flags.bit_subset(5, 1) == 1
    }

    pub fn session_type(&self) -> MatterSessionType {
        match self.flags.bit_subset(0, 2) {
            0 => Unicast,
            1 => Group,
            _ => ReservedForFuture
        }
    }
}