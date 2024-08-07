use std::io::{Cursor, Read};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use crate::secure::protocol::enums::ProtocolOpcode;
use crate::secure::protocol::exchange_flags::ProtocolExchangeFlags;
use crate::secure::protocol::protocol_id::ProtocolID;
use crate::secure::protocol::secured_extensions::ProtocolSecuredExtensions;
use crate::utils::MatterError;

#[derive(Debug, Eq, PartialEq)]
pub struct ProtocolMessage {
    pub exchange_flags: ProtocolExchangeFlags,
    pub opcode: ProtocolOpcode,
    pub exchange_id: u16,
    pub protocol_vendor_id: Option<u16>,
    pub protocol_id: ProtocolID,
    pub acknowledged_message_counter: Option<u32>,
    pub secured_extensions: Option<ProtocolSecuredExtensions>,
    pub payload: Vec<u8>,
}

impl ProtocolMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data: Vec<u8> = vec![];
        data.write_u8(self.exchange_flags.byte).expect("Unable to write exchange flags...");
        data.write_u8(self.opcode.clone() as u8).expect("Unable to write opcode...");
        data.write_u16::<LittleEndian>(self.exchange_id).expect("Unable to write exchange id...");
        match self.protocol_vendor_id {
            Some(vendor) => data.write_u16::<LittleEndian>(vendor).expect("Unable to write vendor id..."),
            None => {}
        }
        data.write_u16::<LittleEndian>(self.protocol_id.clone() as u16).expect("Unable to write Protocol id...");
        match self.acknowledged_message_counter {
            None => {}
            Some(counter) => data.write_u32::<LittleEndian>(counter).expect("Unable to write ACK message counter...")
        }
        match &self.secured_extensions {
            None => {}
            Some(extensions) => {
                data.write_u16::<LittleEndian>(extensions.data_length).expect("Unable to write Extensions Data Length...");
                data.extend(&extensions.data);
            }
        }
        data.extend(&self.payload);
        return data;
    }
}

impl TryFrom<&[u8]> for ProtocolMessage {
    type Error = MatterError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut cursor = Cursor::new(value);
        let exchange_flags = ProtocolExchangeFlags { byte: cursor.read_u8()? };
        let opcode = cursor.read_u8()?;
        let exchange_id = cursor.read_u16::<LittleEndian>()?;
        let protocol_vendor_id = if exchange_flags.is_vendor_present() { Some(cursor.read_u16::<LittleEndian>()?) } else { None };
        let protocol_id = cursor.read_u16::<LittleEndian>()?;
        let acknowledged_message_counter = if exchange_flags.is_acknowledgement() { Some(cursor.read_u32::<LittleEndian>()?) } else { None };
        let secured_extensions = if exchange_flags.is_secured_extensions_present() {
            let data_length = cursor.read_u16::<LittleEndian>()?;
            let mut extensions_vec: Vec<u8> = vec![0; data_length as usize];
            cursor.read(&mut extensions_vec)?;
            Some(ProtocolSecuredExtensions { data_length, data: extensions_vec })
        } else {
            None
        };
        let mut payload: Vec<u8> = vec![];
        cursor.read_to_end(&mut payload)?;

        Ok(Self {
            exchange_flags,
            opcode: ProtocolOpcode::from(opcode),
            exchange_id,
            protocol_vendor_id,
            protocol_id: ProtocolID::from(protocol_id),
            acknowledged_message_counter,
            secured_extensions,
            payload,
        })
    }
}

