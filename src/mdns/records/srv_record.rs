use byteorder::{WriteBytesExt, BE};

use crate::mdns::packet::encode_label;
use crate::mdns::records::SRVRecord;

impl From<SRVRecord> for Vec<u8> {
    fn from(value: SRVRecord) -> Self {
        let mut buffer: Vec<u8> = vec![];
        let encoded_label: Vec<u8> = encode_label(&value.target);
        let total_length = encoded_label.len() + 6;
        buffer.write_u16::<BE>(total_length as u16).unwrap();
        buffer.write_u16::<BE>(value.priority).unwrap();
        buffer.write_u16::<BE>(value.weight).unwrap();
        buffer.write_u16::<BE>(value.port).unwrap();
        buffer.extend(encoded_label);
        buffer
    }
}
