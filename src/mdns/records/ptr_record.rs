use std::io::Write;

use byteorder::{BigEndian, WriteBytesExt};

use crate::mdns::packet::encode_label;
use crate::mdns::records::PTRRecord;

impl Into<Vec<u8>> for PTRRecord<'_> {
    fn into(self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![];
        let encoded_label = encode_label(&self.domain);
        buffer.write_u16::<BigEndian>(encoded_label.len() as u16).unwrap();
        buffer.write_all(&encoded_label).unwrap();
        println!("{}", buffer.iter().map(|x| format!("{:02x}", x)).collect::<Vec<String>>().join(" "));
        return buffer;
    }
}