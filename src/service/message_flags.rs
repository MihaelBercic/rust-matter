use crate::service::enums::MatterDestinationType;
use crate::service::enums::MatterDestinationType::{GroupID, NodeID};
use crate::utils::bit_subset::BitSubset;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct MatterMessageFlags {
    pub(crate) flags: u8,
}

impl MatterMessageFlags {
    pub fn version(&self) -> u8 {
        self.flags >> 4
    }

    pub fn is_source_present(&self) -> bool {
        self.flags.bit_subset(2, 1) == 1
    }

    pub fn type_of_destination(&self) -> Option<MatterDestinationType> {
        let destination = self.flags.bit_subset(0, 2);
        return match destination {
            1 => Some(NodeID),
            2 => Some(GroupID),
            _ => None
        };
    }

    pub fn set_version(&mut self, version: u8) -> &mut Self {
        self.flags.set_bits(4..=7, version);
        return self;
    }

    pub fn set_is_source_present(&mut self, is_present: bool) -> &mut Self {
        self.flags.set_bits(2..=2, is_present as u8);
        return self;
    }

    pub fn set_type_of_destination(&mut self, destination: MatterDestinationType) -> &mut Self {
        let value = match destination {
            GroupID => 2,
            NodeID => 1,
        };
        self.flags.set_bits(0..=2, value);
        return self;
    }
}