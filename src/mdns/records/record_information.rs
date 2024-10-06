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

impl From<RecordInformation> for Vec<u8> {
    fn from(value: RecordInformation) -> Self {
        let mut buffer: Vec<u8> = vec![];
        let mut flags = value.flags;
        flags |= value.class_code;
        buffer.write_all(&encode_label(&value.label)).unwrap();
        buffer.write_u16::<BigEndian>(value.record_type.into()).unwrap();
        buffer.write_u16::<BigEndian>(flags).unwrap();
        buffer
    }
}