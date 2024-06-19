use std::io::{Cursor, Read};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::discovery::mdns::structs::BitSubset;
use crate::service::protocol::structs::{ProtocolExchangeFlags, ProtocolMessage, ProtocolSecuredExtensions};
use crate::useful::MatterError;

impl ProtocolExchangeFlags {
    /// A flag bit indicates whether the message was sent by the initiator.
    pub fn sent_by_initiator(&self) -> bool {
        self.byte.bit_subset(0, 1) == 1
    }

    /// A flag bit indicates whether this message serves as an acknowledgement.
    pub fn is_acknowledgement(&self) -> bool {
        self.byte.bit_subset(1, 1) == 1
    }

    /// A flag bit indicates whether the sender requests for acknowledgment packet.
    pub fn needs_acknowledgement(&self) -> bool {
        self.byte.bit_subset(2, 1) == 1
    }

    /// A flag bit indicates whether secured extensions are present in the packet.
    pub fn is_secured_extensions_present(&self) -> bool {
        self.byte.bit_subset(3, 1) == 1
    }

    /// A flag bit indicates whether vendor information is present in the packet.
    pub fn is_vendor_present(&self) -> bool {
        self.byte.bit_subset(4, 1) == 1
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