use std::io::Write;

use byteorder::{WriteBytesExt, BE};

use crate::mdns::packet::encode_label;
use crate::mdns::records::PTRRecord;

impl From<PTRRecord<'_>> for Vec<u8> {
    fn from(value: PTRRecord<'_>) -> Self {
        let mut buffer: Vec<u8> = vec![];
        let encoded_label = encode_label(&value.domain);
        buffer.write_u16::<BE>(encoded_label.len() as u16).unwrap();
        buffer.write_all(&encoded_label).unwrap();
        buffer
    }
}
