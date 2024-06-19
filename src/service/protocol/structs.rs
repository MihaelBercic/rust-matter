use std::fmt::Display;

use crate::discovery::mdns::structs::BitSubset;

pub const PROTOCOL_ID_SECURE_CHANNEL: u16 = 0x0000;
pub const PROTOCOL_ID_INTERACTION_MODEL: u16 = 0x0001;
pub const PROTOCOL_ID_BDX: u16 = 0x0002;
pub const PROTOCOL_ID_USER_DIRECTED_COMMISSIONING: u16 = 0x0003;
pub const PROTOCOL_ID_FOR_TESTING: u16 = 0x0004;

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

#[derive(Debug)]
pub struct ProtocolExchangeFlags {
    pub byte: u8,
}

#[derive(Debug)]
pub struct ProtocolSecuredExtensions {
    pub data_length: u16,
    pub data: Vec<u8>,
}

pub struct ProtocolMessageBuilder {
    message: ProtocolMessage,
}


impl ProtocolMessageBuilder {
    pub fn new() -> Self {
        Self {
            message: ProtocolMessage {
                exchange_flags: ProtocolExchangeFlags { byte: 0 },
                opcode: 0,
                exchange_id: 0,
                protocol_vendor_id: None,
                protocol_id: 0,
                acknowledged_message_counter: None,
                secured_extensions: None,
                payload: vec![],
            }
        }
    }

    pub fn set_opcode(mut self, opcode: u8) -> Self {
        self.message.opcode = opcode;
        self
    }

    /// A flag bit indicates whether the message was sent by the initiator.
    pub fn sent_by_initiator(mut self, sent_by_initiator: bool) -> Self {
        self
    }

    /// A flag bit indicates whether this message serves as an acknowledgement.
    pub fn set_is_acknowledgement(&self, is_acknowledgement: bool) -> bool {
        self.message.exchange_flags.byte.set_bits(1..=1, is_acknowledgement as u8);
        todo!("self.byte.bit_subset(1, 1) == 1");
    }

    /// A flag bit indicates whether the sender requests for acknowledgment packet.
    pub fn needs_acknowledgement(&self) -> bool {
        todo!("self.byte.bit_subset(2, 1) == 1")
    }

    /// A flag bit indicates whether secured extensions are present in the packet.
    pub fn is_secured_extensions_present(&self) -> bool {
        todo!("self.byte.bit_subset(3, 1) == 1")
    }

    /// A flag bit indicates whether vendor information is present in the packet.
    pub fn is_vendor_present(&self) -> bool {
        todo!("self.byte.bit_subset(4, 1) == 1")
    }

    pub fn build(self) -> ProtocolMessage {
        self.message
    }
}