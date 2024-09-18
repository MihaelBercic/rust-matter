use crate::secure::protocol::enums::{GeneralCode, ProtocolCode};
use crate::secure::protocol::message::ProtocolMessage;
use crate::secure::protocol::protocol_id::ProtocolID;
use crate::utils::MatterError;
use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use std::io::{Cursor, Read};

///
/// @author Mihael Berčič
/// @date 11. 9. 24
///
#[derive(Debug)]
pub struct StatusReport {
    pub general_code: GeneralCode,
    pub protocol_id: ProtocolID,
    pub protocol_code: ProtocolCode,
    pub data: Vec<u8>,
}

impl TryFrom<ProtocolMessage> for StatusReport {
    type Error = MatterError;

    fn try_from(value: ProtocolMessage) -> Result<Self, Self::Error> {
        let mut cursor = Cursor::new(value.payload);
        let mut data = vec![];
        let general_code = GeneralCode::from(cursor.read_u16::<LE>()?);
        let protocol_id = ProtocolID::from(cursor.read_u32::<LE>()?);
        let protocol_code = ProtocolCode::from(cursor.read_u16::<LE>()?);
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

impl StatusReport {
    pub fn new(general_code: GeneralCode, protocol_id: ProtocolID, protocol_code: ProtocolCode) -> Self {
        Self {
            general_code,
            protocol_id,
            protocol_code,
            data: vec![],
        }
    }

    pub fn append_data(&mut self, data: &[u8]) -> &mut Self {
        self.data.extend_from_slice(data);
        self
    }

    pub fn to_bytes(self) -> Vec<u8> {
        let mut data = vec![];
        data.write_u16::<LE>(self.general_code as u16);
        data.write_u32::<LE>(self.protocol_id as u32);
        data.write_u16::<LE>(self.protocol_code as u16);
        data.extend_from_slice(&self.data);
        data
    }
}