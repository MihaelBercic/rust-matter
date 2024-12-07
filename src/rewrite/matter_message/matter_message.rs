use crate::utils::MatterError;
use std::io::{Cursor, Read};

use super::header::MatterMessageHeader;

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
        let contains_mic = !header.is_insecure_unicast_session();
        let left = value.len() - reader.position() as usize;
        let mut payload: Vec<u8> = vec![0u8; left];
        reader.read_exact(&mut payload)?;
        let mut integrity_check: Vec<u8> = vec![];
        if contains_mic {
            reader.read_to_end(&mut integrity_check)?;
        }
        Ok(Self { header, payload, integrity_check })
    }
}

impl From<MatterMessage> for Vec<u8> {
    fn from(value: MatterMessage) -> Self {
        let mut data: Vec<u8> = value.header.into();
        data.extend(&value.payload);
        data.extend(&value.integrity_check);
        data
    }
}
