use crate::discovery::mdns::structs::BitSubset;
use crate::service::enums::MatterDestinationID;
use crate::service::enums::MatterDestinationID::{GroupID, NodeID};

#[derive(Debug)]
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

    pub fn type_of_destination(&self) -> Option<MatterDestinationID> {
        let destination = self.flags.bit_subset(0, 2);
        return match destination {
            1 => Some(NodeID),
            2 => Some(GroupID),
            _ => None
        };
    }
}