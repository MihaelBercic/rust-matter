use crate::session::protocol::exchange_flags::ProtocolExchangeFlags;
use crate::session::protocol::protocol_id::ProtocolID;
use crate::session::protocol::secured_extensions::ProtocolSecuredExtensions;
use crate::session::protocol_message::ProtocolMessage;
use crate::utils::bit_subset::BitSubset;

pub struct ProtocolMessageBuilder {
    message: ProtocolMessage,
}

impl ProtocolMessageBuilder {
    /// Returns new, clean protocol message builder.
    pub fn new() -> Self {
        Self {
            message: ProtocolMessage {
                exchange_flags: ProtocolExchangeFlags { byte: 0 },
                opcode: 0,
                exchange_id: 0,
                protocol_vendor_id: None,
                protocol_id: ProtocolID::ProtocolSecureChannel,
                acknowledged_message_counter: None,
                secured_extensions: None,
                payload: vec![],
            }
        }
    }


    /// Sets the opcode of the message.
    pub fn set_opcode(mut self, opcode: u8) -> Self {
        self.message.opcode = opcode;
        self
    }

    /// Sets the flag bit that indicates whether the message was sent by the initiator.
    pub fn set_is_sent_by_initiator(mut self, sent_by_initiator: bool) -> Self {
        self.message.exchange_flags.byte.set_bits(0..=0, sent_by_initiator as u8);
        self
    }

    /// Sets the flag bit that indicates whether this message serves as an acknowledgement.
    pub fn set_is_acknowledgement(mut self, is_acknowledgement: bool) -> Self {
        self.message.exchange_flags.byte.set_bits(1..=1, is_acknowledgement as u8);
        self
    }

    /// Sets the flag bit that indicates whether the sender is requesting for acknowledgment packet.
    pub fn set_needs_acknowledgement(mut self, needs_acknowledgement: bool) -> Self {
        self.message.exchange_flags.byte.set_bits(2..=2, needs_acknowledgement as u8);
        self
    }

    /// Sets the exchange id of the message.
    pub fn set_exchange_id(mut self, exchange_id: u16) -> Self {
        self.message.exchange_id = exchange_id;
        self
    }

    /// Sets the vendor id as well as the flag indicating that the vendor id is present.
    pub fn set_vendor(mut self, vendor: u16) -> Self {
        self.message.protocol_vendor_id = Some(vendor);
        self.set_is_vendor_present(true)
    }

    /// Sets the message protocol.
    pub fn set_protocol(mut self, protocol_id: ProtocolID) -> Self {
        self.message.protocol_id = protocol_id;
        self
    }

    /// Sets the secure_channel extensions as well as the flag indicating the extensions are present.
    pub fn set_secure_extensions(mut self, extensions: ProtocolSecuredExtensions) -> Self {
        self.message.secured_extensions = Some(extensions);
        self.set_is_secured_extensions_present(true)
    }

    /// Sets the counter of the message.
    pub fn set_acknowledged_message_counter(mut self, counter: u32) -> Self {
        self.message.acknowledged_message_counter = Some(counter);
        self.set_is_acknowledgement(true)
    }

    /// Sets the flag bit that indicates whether secured extensions are present in the packet.
    fn set_is_secured_extensions_present(mut self, is_present: bool) -> Self {
        self.message.exchange_flags.byte.set_bits(3..=3, is_present as u8);
        self
    }

    /// Sets the flag bit that indicates whether vendor information is present in the packet.
    fn set_is_vendor_present(mut self, is_present: bool) -> Self {
        self.message.exchange_flags.byte.set_bits(4..=4, is_present as u8);
        self
    }

    /// Sets the payload of the [Protocol Message](ProtocolMessage).
    pub fn set_payload(mut self, payload: &[u8]) -> Self {
        self.message.payload.clear();
        self.message.payload.extend_from_slice(payload);
        self
    }

    /// Returns the built [ProtocolMessage].
    pub fn build(self) -> ProtocolMessage {
        self.message
    }
}