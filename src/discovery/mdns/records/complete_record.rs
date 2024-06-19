use std::io::Write;

use byteorder::{BigEndian, WriteBytesExt};

use crate::discovery::mdns::records::record_information::RecordInformation;

#[derive(Debug, Clone)]
pub struct CompleteRecord {
    pub record_information: RecordInformation,
    pub ttl: u32,
    pub data: Vec<u8>,
}

impl Into<Vec<u8>> for CompleteRecord {
    fn into(self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![];
        let record_information: Vec<u8> = self.record_information.into();
        buffer.extend(record_information);
        buffer.write_u32::<BigEndian>(self.ttl).unwrap();
        buffer.write_all(&self.data).unwrap();
        return buffer;
    }
}