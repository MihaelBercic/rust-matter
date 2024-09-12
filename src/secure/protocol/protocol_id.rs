use crate::secure::protocol::protocol_id::ProtocolID::*;

///
/// @author Mihael Berčič
/// @date 6. 8. 24
///
#[repr(u8)]
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum ProtocolID {
    ProtocolSecureChannel = 0x0000,
    ProtocolInteractionModel = 0x0001,
    ProtocolBdx = 0x0002,
    ProtocolUserDirectedCommissioning = 0x0003,
    ProtocolForTesting = 0x0004,
}

impl From<u16> for ProtocolID {
    fn from(value: u16) -> Self {
        match value {
            0x0000 => ProtocolSecureChannel,
            0x0001 => ProtocolInteractionModel,
            0x0002 => ProtocolBdx,
            0x0003 => ProtocolUserDirectedCommissioning,
            _ => ProtocolForTesting
        }
    }
}