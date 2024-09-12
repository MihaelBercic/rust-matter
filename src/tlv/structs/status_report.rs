use crate::secure::protocol::message::ProtocolMessage;
use crate::utils::MatterError;
use byteorder::{ReadBytesExt, LE};
use std::io::{Cursor, Read};

///
/// @author Mihael Berčič
/// @date 11. 9. 24
///
#[derive(Debug)]
pub struct StatusReport {
    general_code: u16,
    protocol_id: u32,
    protocol_code: u16,
    data: Vec<u8>,
}

impl TryFrom<ProtocolMessage> for StatusReport {
    type Error = MatterError;

    fn try_from(value: ProtocolMessage) -> Result<Self, Self::Error> {
        let mut cursor = Cursor::new(value.payload);
        let mut data = vec![];
        let general_code = cursor.read_u16::<LE>()?;
        let protocol_id = cursor.read_u32::<LE>()?;
        let protocol_code = cursor.read_u16::<LE>()?;
        cursor.read_to_end(&mut data)?;
        Ok(
            Self {
                general_code,
                protocol_id,
                protocol_code,
                data,
            }
        )
    }
}