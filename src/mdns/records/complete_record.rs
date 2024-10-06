use std::io::Write;

use byteorder::{BigEndian, WriteBytesExt};

use crate::mdns::records::record_information::RecordInformation;

#[derive(Debug, Clone)]
pub struct CompleteRecord {
    pub record_information: RecordInformation,
    pub ttl: u32,
    pub data: Vec<u8>,
}

impl From<CompleteRecord> for Vec<u8> {
    fn from(value: CompleteRecord) -> Self {
        let mut buffer: Vec<u8> = vec![];
        let record_information: Vec<u8> = value.record_information.into();
        buffer.extend(record_information);
        buffer.write_u32::<BigEndian>(value.ttl).unwrap();
        buffer.write_all(&value.data).unwrap();
        buffer
    }
}