use byteorder::{BigEndian, WriteBytesExt};

use crate::discovery::mdns::packet::encode_label;
use crate::discovery::mdns::records::SRVRecord;

impl Into<Vec<u8>> for SRVRecord {
    fn into(self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![];
        let encoded_label: Vec<u8> = encode_label(&self.target);
        let total_length = encoded_label.len() + 6;
        buffer.write_u16::<BigEndian>(total_length as u16).unwrap();
        buffer.write_u16::<BigEndian>(self.priority).unwrap();
        buffer.write_u16::<BigEndian>(self.weight).unwrap();
        buffer.write_u16::<BigEndian>(self.port).unwrap();
        buffer.extend(encoded_label);
        return buffer;
    }
}