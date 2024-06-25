use std::io::Write;

use byteorder::{BigEndian, WriteBytesExt};

use crate::mdns::packet::encode_label;
use crate::mdns::records::record_type::RecordType;

///
/// @author Mihael Berčič
/// @date 19. 6. 24
///
#[derive(Debug, Clone)]
pub struct RecordInformation {
    pub label: String,
    pub record_type: RecordType,
    pub flags: u16,
    pub class_code: u16,
    pub has_property: bool,
}

impl Into<Vec<u8>> for RecordInformation {
    fn into(mut self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![];
        self.flags |= self.class_code;
        buffer.write_all(&encode_label(&self.label)).unwrap();
        buffer.write_u16::<BigEndian>(self.record_type.into()).unwrap();
        buffer.write_u16::<BigEndian>(self.flags).unwrap();
        return buffer;
    }
}
