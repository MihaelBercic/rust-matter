use std::iter;
use std::io::Cursor;

use crate::{
    rewrite::enums::{DestinationID, DestinationType, SessionType},
    utils::MatterError,
};
use byteorder::{ReadBytesExt, WriteBytesExt, LE};

use super::{extension::MessageExtension, flags::MatterMessageFlags, security_flags::MatterSecurityFlags};

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct MatterMessageHeader {
    pub flags: MatterMessageFlags,
    pub session_id: u16,
    pub security_flags: MatterSecurityFlags,
    pub message_counter: u32,
    pub source_node_id: Option<u64>,
    pub destination_node_id: Option<DestinationID>,
    pub message_extensions: Option<MessageExtension>,
}

impl MatterMessageHeader {
    /// Read if the session is unicast (single) and **secure**.
    pub fn is_secure_unicast_session(&self) -> bool {
        self.session_id != 0 && self.security_flags.session_type() == SessionType::Unicast
    }

    /// Read if the session is unicast (single) and **insecure**.
    pub fn is_insecure_unicast_session(&self) -> bool {
        self.session_id == 0 && self.security_flags.session_type() == SessionType::Unicast
    }

    /// Read if the session is unicast (single) or group (multiple).
    pub fn is_group_session(&self) -> bool {
        self.security_flags.session_type() == SessionType::Group
    }
}

impl TryFrom<&mut Cursor<&[u8]>> for MatterMessageHeader {
    type Error = MatterError;

    fn try_from(value: &mut Cursor<&[u8]>) -> Result<Self, MatterError> {
        let flags = MatterMessageFlags { flags: value.read_u8()? };
        let session_id = value.read_u16::<LE>()?;
        let security_flags = MatterSecurityFlags { flags: value.read_u8()? };
        let message_counter = value.read_u32::<LE>()?;
        let source_node_id = match flags.is_source_present() {
            true => Some(value.read_u64::<LE>()?),
            false => None,
        };
        let destination_node_id = match flags.type_of_destination() {
            Some(destination_type) => match destination_type {
                DestinationType::NodeID => Some(DestinationID::Node(value.read_u64::<LE>()?)),
                DestinationType::GroupID => Some(DestinationID::Group(value.read_u16::<LE>()?)),
            },
            _ => None,
        };

        let message_extensions = match security_flags.has_message_extensions() {
            false => None,
            true => {
                let length = value.read_u16::<LE>()?;
                let data: Vec<u8> = iter::repeat(0u8).take(length as usize).collect();
                Some(MessageExtension { data })
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
}

impl From<MatterMessageHeader> for Vec<u8> {
    /// Return the byte representation of Matter Message Header.
    fn from(value: MatterMessageHeader) -> Self {
        let mut data = vec![];
        data.write_u8(value.flags.flags).expect("Unable to write flags...");
        data.write_u16::<LE>(value.session_id).expect("Unable to write session id...");
        data.write_u8(value.security_flags.flags).expect("Unable to write security flags...");
        data.write_u32::<LE>(value.message_counter).expect("Unable to write message counter...");

        if let Some(id) = value.source_node_id {
            data.write_u64::<LE>(id).expect("Unable to write Source Node ID...");
        }

        match value.destination_node_id {
            Some(DestinationID::Group(id)) => data.write_u16::<LE>(id).expect("Unable to write NodeID..."),
            Some(DestinationID::Node(id)) => data.write_u64::<LE>(id).expect("Unable to write NodeID..."),
            _ => (),
        }

        if let Some(extensions) = &value.message_extensions {
            data.write_u16::<LE>(extensions.data.len() as u16).expect("Unable to write message extensions length...");
            data.extend_from_slice(&extensions.data);
        }

        data
    }
}
