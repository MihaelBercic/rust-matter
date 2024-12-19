use crate::utils::MatterError;
use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use std::io::{Cursor, Read};

use super::{enums::ProtocolID, exchange_flags::ProtocolExchangeFlags, secured_extensions::ProtocolSecuredExtensions};

#[derive(Debug, Eq, PartialEq)]
pub struct ProtocolMessage {
    pub exchange_flags: ProtocolExchangeFlags,
    pub opcode: u8,
    pub exchange_id: u16,
    pub protocol_vendor_id: Option<u16>,
    pub protocol_id: ProtocolID,
    pub acknowledged_message_counter: Option<u32>,
    pub secured_extensions: Option<ProtocolSecuredExtensions>,
    pub payload: Vec<u8>,
}

impl From<ProtocolMessage> for Vec<u8> {
    fn from(value: ProtocolMessage) -> Self {
        let mut data: Vec<u8> = vec![];
        data.write_u8(value.exchange_flags.byte).expect("Unable to write exchange flags...");
        data.write_u8(value.opcode.clone() as u8).expect("Unable to write opcode...");
        data.write_u16::<LE>(value.exchange_id).expect("Unable to write exchange id...");

        if let Some(vendor) = value.protocol_vendor_id {
            data.write_u16::<LE>(vendor).expect("Unable to write vendor id...");
        }

        data.write_u16::<LE>(value.protocol_id.clone() as u16).expect("Unable to write Protocol id...");
        if let Some(counter) = value.acknowledged_message_counter {
            data.write_u32::<LE>(counter).expect("Unable to write ACK message counter...");
        }

        if let Some(extensions) = &value.secured_extensions {
            data.write_u16::<LE>(extensions.data_length).expect("Unable to write Extensions Data Length...");
            data.extend(&extensions.data);
        }
        data.extend(&value.payload);
        data
    }
}

impl TryFrom<&[u8]> for ProtocolMessage {
    type Error = MatterError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut cursor = Cursor::new(value);
        let exchange_flags = ProtocolExchangeFlags { byte: cursor.read_u8()? };
        let opcode = cursor.read_u8()?;
        let exchange_id = cursor.read_u16::<LE>()?;
        let protocol_vendor_id = if exchange_flags.is_vendor_present() { Some(cursor.read_u16::<LE>()?) } else { None };
        let protocol_id = ProtocolID::from(cursor.read_u16::<LE>()?);
        let acknowledged_message_counter = if exchange_flags.is_acknowledgement() { Some(cursor.read_u32::<LE>()?) } else { None };
        let secured_extensions = if exchange_flags.is_secured_extensions_present() {
            let data_length = cursor.read_u16::<LE>()?;
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
