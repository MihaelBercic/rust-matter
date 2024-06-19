use std::io::Cursor;
use std::iter;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::service::enums::{MatterDestinationID, MatterSessionType};
use crate::service::enums::MatterDestinationID::{GroupID, NodeID};
use crate::service::enums::MatterSessionType::Unicast;
use crate::service::message_extension::MatterMessageExtension;
use crate::service::message_flags::MatterMessageFlags;
use crate::service::security_flags::MatterSecurityFlags;
use crate::utils::MatterError;

#[derive(Debug)]
pub struct MatterMessageHeader {
    pub flags: MatterMessageFlags,
    pub session_id: u16,
    pub security_flags: MatterSecurityFlags,
    pub message_counter: u32,
    pub source_node_id: Option<u64>,
    pub destination_node_id: Option<MatterDestinationID>,
    pub message_extensions: Option<MatterMessageExtension>,
}

impl MatterMessageHeader {
    pub fn try_from(reader: &mut Cursor<&[u8]>) -> Result<Self, MatterError> {
        let flags = MatterMessageFlags { flags: reader.read_u8()? };
        let session_id = reader.read_u16::<LittleEndian>()?;
        let security_flags = MatterSecurityFlags { flags: reader.read_u8()? };
        let message_counter = reader.read_u32::<LittleEndian>()?;
        let source_node_id: Option<u64> = if flags.is_source_present() {
            Some(reader.read_u64::<LittleEndian>()?)
        } else {
            None
        };
        let destination_node_id = match flags.type_of_destination() {
            Some(NodeID) => Some(MatterDestinationID::Node(reader.read_u64::<LittleEndian>()?)),
            Some(GroupID) => Some(MatterDestinationID::Group(reader.read_u16::<LittleEndian>()?)),
            _ => None
        };

        let message_extensions = match security_flags.has_message_extensions() {
            false => None,
            true => {
                let length = reader.read_u16::<LittleEndian>()?;
                let data: Vec<u8> = iter::repeat(0u8).take(length as usize).collect();
                Some(MatterMessageExtension { data })
            }
        };

        Ok(Self {
            flags,
            session_id,
            security_flags,
            message_counter,
            source_node_id,
            destination_node_id,
            message_extensions,
        })
    }

    pub fn is_secure_unicast_session(&self) -> bool {
        self.session_id != 0 && self.security_flags.session_type() == Unicast
    }

    pub fn is_unsecured_unicast_sesson(&self) -> bool {
        self.session_id == 0 && self.security_flags.session_type() == Unicast
    }

    pub fn is_group_session(&self) -> bool {
        self.security_flags.session_type() == MatterSessionType::Group
    }
}
