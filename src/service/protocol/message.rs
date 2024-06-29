use std::io::{Cursor, Read};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::service::protocol::exchange_flags::ProtocolExchangeFlags;
use crate::service::protocol::secured_extensions::ProtocolSecuredExtensions;
use crate::utils::MatterError;

#[derive(Debug)]
pub struct ProtocolMessage {
    pub exchange_flags: ProtocolExchangeFlags,
    pub opcode: u8,
    pub exchange_id: u16,
    pub protocol_vendor_id: Option<u16>,
    pub protocol_id: u16,
    pub acknowledged_message_counter: Option<u32>,
    pub secured_extensions: Option<ProtocolSecuredExtensions>,
    pub payload: Vec<u8>,
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
            opcode,
            exchange_id,
            protocol_vendor_id,
            protocol_id,
            acknowledged_message_counter,
            secured_extensions,
            payload,
        })
    }
}