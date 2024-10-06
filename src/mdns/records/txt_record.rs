use crate::mdns::records::TXTRecord;
use byteorder::{WriteBytesExt, BE};

impl From<TXTRecord<'static>> for Vec<u8> {
    fn from(value: TXTRecord<'static>) -> Self {
        let mut buffer: Vec<u8> = vec![];
        let mapped = value.pairs.iter().map(|(key, value)| format!("{}={}", key, value)).collect::<Vec<String>>();
        let total_length = (mapped.join("").len() + mapped.len()) as u16;
        buffer.write_u16::<BE>(total_length).unwrap();
        for value in mapped {
            buffer.push(value.len() as u8);
            buffer.extend(value.as_bytes());
        }
        buffer
    }
}