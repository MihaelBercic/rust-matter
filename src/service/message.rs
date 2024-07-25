use std::io::{Cursor, Read};

use crate::service::message_header::MatterMessageHeader;
use crate::utils::MatterError;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct MatterMessage {
    pub header: MatterMessageHeader,
    pub payload: Vec<u8>,
    pub integrity_check: Vec<u8>,
}

impl TryFrom<&[u8]> for MatterMessage {
    type Error = MatterError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut reader = Cursor::new(value);
        let header = MatterMessageHeader::try_from(&mut reader)?;
        let contains_mic = !header.is_unsecured_unicast_session();
        let left = value.len() - reader.position() as usize;
        let mut payload: Vec<u8> = vec![0u8; left];
        reader.read_exact(&mut payload)?;
        let mut integrity_check: Vec<u8> = vec![];
        if contains_mic { reader.read_to_end(&mut integrity_check)?; }
        Ok(Self {
            header,
            payload,
            integrity_check,
        })
    }
}

impl MatterMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = vec![];
        let header_as_bytes = &self.header.to_bytes();
        data.extend_from_slice(&header_as_bytes);
        data.extend(&self.payload);
        data.extend(&self.integrity_check);
        data
    }
}