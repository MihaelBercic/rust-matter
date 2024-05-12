use std::{io, iter};
use std::io::{Cursor, Read};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::discovery::mdns::structs::BitSubset;
use crate::service::structs::{MatterDestinationID, MatterMessage, MatterMessageExtension, MatterMessageFlags, MatterMessageHeader, MatterSecurityFlags, MatterSessionType};
use crate::service::structs::MatterSessionType::{Group, ReservedForFuture, Unicast};

impl TryFrom<&[u8]> for MatterMessage {
    type Error = io::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut reader = Cursor::new(value);
        let header = MatterMessageHeader::try_from(&mut reader)?;
        let mut payload: Vec<u8> = vec![0u8; header.payload_length as usize];
        reader.read_exact(&mut payload)?;
        let mut integrity_check: Vec<u8> = vec![];
        reader.read_to_end(&mut integrity_check)?;
        Ok(Self {
            header,
            payload,
            integrity_check,
        })
    }
}

impl MatterMessageHeader {
    fn try_from(reader: &mut Cursor<&[u8]>) -> Result<Self, io::Error> {
        let payload_length = reader.read_u16::<LittleEndian>()?;
        let flags = MatterMessageFlags { flags: reader.read_u8()? };
        let session_id = reader.read_u16::<LittleEndian>()?;
        let security_flags = MatterSecurityFlags { flags: reader.read_u8()? };
        let message_counter = reader.read_u32::<LittleEndian>()?;
        let source_node_id: Option<[u8; 8]> = if flags.is_source_present() {
            let mut buff = [0u8; 8];
            reader.read_exact(&mut buff)?;
            Some(buff)
        } else {
            None
        };
        let destination_node_id = match flags.type_of_destination() {
            Some(MatterDestinationID::LongGroupID) => Some(MatterDestinationID::Long(reader.read_u64::<LittleEndian>()?)),
            Some(MatterDestinationID::ShortGroupID) => Some(MatterDestinationID::Short(reader.read_u16::<LittleEndian>()?)),
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
            payload_length,
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

impl MatterMessageFlags {
    fn version(&self) -> u8 {
        self.flags >> 4
    }

    fn is_source_present(&self) -> bool {
        self.flags.bit_subset(2, 1) == 1
    }

    fn type_of_destination(&self) -> Option<MatterDestinationID> {
        let destination = self.flags.bit_subset(0, 2);
        return match destination {
            1 => Some(MatterDestinationID::LongGroupID),
            2 => Some(MatterDestinationID::ShortGroupID),
            _ => None
        };
    }
}

impl MatterSecurityFlags {
    fn is_encoded_with_privacy(&self) -> bool {
        self.flags.bit_subset(7, 1) == 1
    }

    fn is_control_message(&self) -> bool {
        self.flags.bit_subset(6, 1) == 1
    }

    fn has_message_extensions(&self) -> bool {
        self.flags.bit_subset(5, 1) == 1
    }

    fn session_type(&self) -> MatterSessionType {
        match self.flags.bit_subset(0, 2) {
            0 => Unicast,
            1 => Group,
            _ => ReservedForFuture
        }
    }
}