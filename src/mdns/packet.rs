use std::io;
use std::io::{Cursor, Read};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use crate::mdns::packet_header::MDNSPacketHeader;
use crate::mdns::records::complete_record::CompleteRecord;
use crate::mdns::records::record_information::RecordInformation;
use crate::mdns::records::record_type::RecordType;
use crate::utils::bit_subset::BitSubset;

///
/// @author Mihael Berčič
/// @date 19. 6. 24
///
#[allow(unused)]
#[derive(Debug)]
pub struct MDNSPacket {
    pub header: MDNSPacketHeader,
    pub query_records: Vec<RecordInformation>,
    pub answer_records: Vec<CompleteRecord>,
    pub authority_records: Vec<CompleteRecord>,
    pub additional_records: Vec<CompleteRecord>,
}

impl TryFrom<&[u8]> for MDNSPacket {
    type Error = io::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut byte_reader = Cursor::new(value);
        let id = byte_reader.read_u16::<BigEndian>()?;
        let flags = byte_reader.read_u16::<BigEndian>()?;
        let header = MDNSPacketHeader::new(id, flags);

        let query_count = byte_reader.read_u16::<BigEndian>()?;
        let answer_count = byte_reader.read_u16::<BigEndian>()?;
        let authority_count = byte_reader.read_u16::<BigEndian>()?;
        let additional_count = byte_reader.read_u16::<BigEndian>()?;

        let query_records: Vec<RecordInformation> = (0..query_count).filter_map(|_| read_record_information(&mut byte_reader).ok()).collect();
        let answer_records: Vec<CompleteRecord> = (0..answer_count).filter_map(|_| read_complete_record(&mut byte_reader, true).ok()).collect();
        let authority_records: Vec<CompleteRecord> = (0..authority_count).filter_map(|_| read_complete_record(&mut byte_reader, true).ok()).collect();
        let additional_records: Vec<CompleteRecord> = (0..additional_count).filter_map(|_| read_complete_record(&mut byte_reader, true).ok()).collect();
        return Ok(MDNSPacket {
            header,
            query_records,
            answer_records,
            authority_records,
            additional_records,
        });
    }
}

impl Into<Vec<u8>> for MDNSPacket {
    fn into(self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![];
        let header: [u8; 4] = self.header.into();
        buffer.extend_from_slice(&header);
        buffer.write_u16::<BigEndian>(self.query_records.len() as u16).unwrap();
        buffer.write_u16::<BigEndian>(self.answer_records.len() as u16).unwrap();
        buffer.write_u16::<BigEndian>(self.authority_records.len() as u16).unwrap();
        buffer.write_u16::<BigEndian>(self.additional_records.len() as u16).unwrap();

        for x in self.query_records { buffer.extend::<Vec<u8>>(x.into()) }
        for x in self.answer_records { buffer.extend::<Vec<u8>>(x.into()) }
        for x in self.authority_records { buffer.extend::<Vec<u8>>(x.into()) }
        for x in self.additional_records { buffer.extend::<Vec<u8>>(x.into()) }

        buffer
    }
}

pub(crate) fn encode_label(label: &str) -> Vec<u8> {
    let mut encoded: Vec<u8> = vec![];
    for x in label.split(".") {
        encoded.push(x.len() as u8);
        encoded.extend_from_slice(x.as_bytes());
    };
    encoded.push(0); // Indicating the end of the label.
    return encoded;
}

pub(crate) fn read_label(buffer: &mut Cursor<&[u8]>) -> Result<String, io::Error> {
    let mut characters: Vec<u8> = vec![];
    let mut return_to: u64 = 0;
    loop {
        let byte = match buffer.read_u8() {
            Ok(b) => { if b == 0 { break; } else { b } }
            Err(_) => { break; }
        };
        let is_pointer = byte >= 0b11000000;
        if is_pointer {
            let byte = byte as u64;
            let next_byte = buffer.read_u8().unwrap() as u64;
            let shifted = (byte & 0b00111111) << 8;
            let position = shifted | next_byte;
            let jump_position = position;
            if return_to == 0 {
                return_to = buffer.position();
            }
            buffer.set_position(jump_position);
        } else {
            let label_length = byte as usize;
            let mut label_slice: Vec<u8> = vec![0u8; label_length];
            buffer.read_exact(&mut label_slice)?;
            if !characters.is_empty() {
                characters.extend_from_slice(".".as_bytes()); // Add dot
            }
            characters.extend(label_slice);
        }
    }
    if return_to > 0 {
        buffer.set_position(return_to);
    }
    let built_string = String::from_utf8(characters).unwrap_or_else(|_| "Unknown".to_string());
    Ok(built_string)
}

pub(crate) fn read_record_information(buffer: &mut Cursor<&[u8]>) -> Result<RecordInformation, io::Error> {
    let label = read_label(buffer)?;
    let record_type = buffer.read_u16::<BigEndian>().unwrap(); // Get Into ENUM value somehow
    let flags = buffer.read_u16::<BigEndian>().unwrap();
    let class_code = flags & (0xFFFF - 1);
    let has_property = flags.bit_subset(15, 1) == 1;
    Ok(RecordInformation {
        label,
        record_type: RecordType::from(record_type),
        flags,
        class_code,
        has_property,
    })
}

pub(crate) fn read_complete_record(buffer: &mut Cursor<&[u8]>, discard_data: bool) -> Result<CompleteRecord, io::Error> {
    let record_information = read_record_information(buffer)?;
    let ttl = buffer.read_u32::<BigEndian>()?;
    let data_length = buffer.read_u16::<BigEndian>()? as u64;
    let mut data: Vec<u8> = vec![];
    if discard_data {
        buffer.set_position(buffer.position() + data_length)
    } else {
        buffer.read_exact(&mut data)?;
    }
    Ok(CompleteRecord {
        record_information,
        ttl,
        data,
    })
}

