use std::io::Cursor;
use std::iter;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use crate::session::matter::enums::MatterSessionType::{Group, Unicast};
use crate::session::matter::enums::{MatterDestinationID, MatterDestinationType};
use crate::session::matter::extension::MatterMessageExtension;
use crate::session::matter::flags::MatterMessageFlags;
use crate::session::matter::security_flags::MatterSecurityFlags;
use crate::utils::MatterError;

#[derive(Debug, Eq, PartialEq, Clone)]
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
    /// Read if the session is unicast (single) and **secure**.
    pub fn is_secure_unicast_session(&self) -> bool {
        self.session_id != 0 && self.security_flags.session_type() == Unicast
    }

    /// Read if the session is unicast (single) and **insecure**.
    pub fn is_insecure_unicast_session(&self) -> bool {
        self.session_id == 0 && self.security_flags.session_type() == Unicast
    }

    /// Read if the session is unicast (single) or group (multiple).
    pub fn is_group_session(&self) -> bool {
        self.security_flags.session_type() == Group
    }

    /// Return the byte representation of Matter Message Header.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = vec![];
        data.write_u8(self.flags.flags).expect("Unable to write flags...");
        data.write_u16::<LittleEndian>(self.session_id).expect("Unable to write session id...");
        data.write_u8(self.security_flags.flags).expect("Unable to write security flags...");
        data.write_u32::<LittleEndian>(self.message_counter).expect("Unable to write message counter...");
        match self.source_node_id {
            Some(id) => data.write_u64::<LittleEndian>(id).expect("Unable to write Source Node ID..."),
            None => {}
        }
        match self.destination_node_id {
            Some(MatterDestinationID::Group(id)) => data.write_u16::<LittleEndian>(id).expect("Unable to write NodeID..."),
            Some(MatterDestinationID::Node(id)) => data.write_u64::<LittleEndian>(id).expect("Unable to write NodeID..."),
            _ => ()
        }

        match &self.message_extensions {
            Some(extensions) => {
                data.write_u16::<LittleEndian>(extensions.data.len() as u16).expect("Unable to write message extensions length...");
                data.extend_from_slice(&extensions.data);
            }
            _ => ()
        }
        data
    }
}

impl TryFrom<&mut Cursor<&[u8]>> for MatterMessageHeader {
    type Error = MatterError;

    fn try_from(value: &mut Cursor<&[u8]>) -> Result<Self, MatterError> {
        let flags = MatterMessageFlags { flags: value.read_u8()? };
        let session_id = value.read_u16::<LittleEndian>()?;
        let security_flags = MatterSecurityFlags { flags: value.read_u8()? };
        let message_counter = value.read_u32::<LittleEndian>()?;
        let source_node_id = match flags.is_source_present() {
            true => Some(value.read_u64::<LittleEndian>()?),
            false => None
        };
        let destination_node_id = match flags.type_of_destination() {
            Some(destination_type) => {
                match destination_type {
                    MatterDestinationType::NodeID => Some(MatterDestinationID::Node(value.read_u64::<LittleEndian>()?)),
                    MatterDestinationType::GroupID => Some(MatterDestinationID::Group(value.read_u16::<LittleEndian>()?)),
                }
            }
            _ => None
        };

        let message_extensions = match security_flags.has_message_extensions() {
            false => None,
            true => {
                let length = value.read_u16::<LittleEndian>()?;
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
}

