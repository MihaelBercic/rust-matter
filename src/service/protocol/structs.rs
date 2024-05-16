const PROTOCOL_ID_SECURE_CHANNEL: u16 = 0x0000;
const PROTOCOL_ID_INTERACTION_MODEL: u16 = 0x0001;
const PROTOCOL_ID_BDX: u16 = 0x0002;
const PROTOCOL_ID_USER_DIRECTED_COMMISSIONING: u16 = 0x0003;
const PROTOCOL_ID_FOR_TESTING: u16 = 0x0004;

pub struct ProtocolMessage {
    pub flags: ProtocolExchangeFlags,
    pub opcode: u8,
    pub exchange_id: u16,
    pub protocol_vendor_id: Option<u16>,
    pub protocol_id: u16,
    pub acknowledged_message_counter: Option<u32>,
    pub secured_extensions: Option<ProtocolSecuredExtensions>,
    pub payload: Vec<u8>,
}

pub struct ProtocolExchangeFlags {
    pub(crate) byte: u8,
}

pub struct ProtocolSecuredExtensions {
    data_length: u16,
    data: Vec<u8>,
}