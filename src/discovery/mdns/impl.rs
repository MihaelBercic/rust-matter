use std::cmp::min;
use std::io::Write;

use byteorder::{BigEndian, WriteBytesExt};

use crate::discovery::mdns::mdns_structs::{BitSubset, CompleteRecord, MDNSPacket, MDNSPacketHeader, RecordInformation, RecordType};
use crate::discovery::mdns::mdns_structs::RecordType::Unsupported;
use crate::useful::byte_reader::ByteReader;

impl From<&[u8]> for MDNSPacket {
    fn from(value: &[u8]) -> Self {
        let mut byte_reader = ByteReader::new(value);
        let id = byte_reader.read_u16::<BigEndian>().unwrap();
        let flags = byte_reader.read_u16::<BigEndian>().unwrap();
        let header = MDNSPacketHeader::new(id, flags);

        let query_count = byte_reader.read_u16::<BigEndian>().unwrap();
        let answer_count = byte_reader.read_u16::<BigEndian>().unwrap();
        let authority_count = byte_reader.read_u16::<BigEndian>().unwrap();
        let additional_count = byte_reader.read_u16::<BigEndian>().unwrap();

        let query_records: Vec<RecordInformation> = (0..query_count).map(|_| read_record_information(&mut byte_reader)).collect();
        let answer_records: Vec<CompleteRecord> = (0..answer_count).map(|_| read_complete_record(&mut byte_reader, true)).collect();
        let authority_records: Vec<CompleteRecord> = (0..authority_count).map(|_| read_complete_record(&mut byte_reader, true)).collect();
        let additional_records: Vec<CompleteRecord> = (0..additional_count).map(|_| read_complete_record(&mut byte_reader, true)).collect();

        // let _: Vec<RecordInformation> = (0..query_count).map(|_| read_record_information(&mut byte_reader)).collect();
        // let _: Vec<CompleteRecord> = (0..answer_count).map(|_| read_complete_record(&mut byte_reader, true)).collect();
        // let _: Vec<CompleteRecord> = (0..authority_count).map(|_| read_complete_record(&mut byte_reader, true)).collect();
        // let _: Vec<CompleteRecord> = (0..additional_count).map(|_| read_complete_record(&mut byte_reader, true)).collect();

        // print!("\033cQC: {}, AnC: {}, AuC: {}, AdC: {}", query_count, answer_count, authority_count, additional_count);
        // println!("Header: {:#?}", header);
        return MDNSPacket {
            header,
            query_records,
            answer_records,
            authority_records,
            additional_records,
        };
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

        return buffer;
    }
}

impl Into<[u8; 4]> for MDNSPacketHeader {
    fn into(self) -> [u8; 4] {
        let mut buf = [0u8; 4];
        let mut flags = 0u16;
        flags |= if self.is_response { 1 } else { 0 };
        flags <<= 4;
        flags |= self.opcode as u16;
        flags <<= 1;
        flags |= if self.is_authoritative_answer { 1 } else { 0 };
        flags <<= 1;
        flags <<= 1;
        flags |= if self.is_recursion_desired { 1 } else { 0 };
        flags <<= 8;

        let id_as_bytes: [u8; 2] = self.identification.to_be_bytes(); // identification is u16
        let flags_as_bytes: [u8; 2] = flags.to_be_bytes(); // flags is u16
        buf[0..2].copy_from_slice(&id_as_bytes);
        buf[2..4].copy_from_slice(&flags_as_bytes);
        println!("FLAGS: {:016b}", flags);
        return buf;
    }
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

impl Clone for RecordType {
    fn clone(&self) -> Self {
        return match self {
            Unsupported(_) => Unsupported(0),
            RecordType::A => RecordType::A,
            RecordType::NS => RecordType::NS,
            RecordType::CNAME => RecordType::CNAME,
            RecordType::SOA => RecordType::SOA,
            RecordType::PTR => RecordType::PTR,
            RecordType::HINFO => RecordType::HINFO,
            RecordType::MX => RecordType::MX,
            RecordType::TXT => RecordType::TXT,
            RecordType::RP => RecordType::RP,
            RecordType::AFSDB => RecordType::AFSDB,
            RecordType::SIG => RecordType::SIG,
            RecordType::KEY => RecordType::KEY,
            RecordType::AAAA => RecordType::AAAA,
            RecordType::LOC => RecordType::LOC,
            RecordType::SRV => RecordType::SRV,
            RecordType::NAPTR => RecordType::NAPTR,
            RecordType::KX => RecordType::KX,
            RecordType::CERT => RecordType::CERT,
            RecordType::DNAME => RecordType::DNAME,
            RecordType::APL => RecordType::APL,
            RecordType::DS => RecordType::DS,
            RecordType::NSEC => RecordType::NSEC,
        };
    }
}

impl Clone for RecordInformation {
    fn clone(&self) -> Self {
        RecordInformation {
            label: self.label.clone(),
            record_type: self.record_type.clone(),
            flags: self.flags,
            class_code: self.class_code,
            has_property: self.has_property,
        }
    }
}

impl Clone for CompleteRecord {
    fn clone(&self) -> Self {
        CompleteRecord {
            record_information: self.record_information.clone(),
            ttl: self.ttl,
            data: self.data.clone(),
        }
    }
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

impl MDNSPacketHeader {
    fn new(id: u16, flags: u16) -> Self {
        let is_response = flags.bit_subset(15, 1) == 1;
        let opcode = flags.bit_subset(11, 4) as u8;
        let is_authoritative_answer = flags.bit_subset(10, 1) == 1;
        let is_truncated = flags.bit_subset(9, 1) == 1;
        let is_recursion_desired = flags.bit_subset(8, 1) == 1;
        let is_recursion_available = flags.bit_subset(7, 1) == 1;
        let response_code = flags.bit_subset(0, 4) as u8;
        return Self {
            identification: id,
            flags,
            is_response,
            opcode,
            is_authoritative_answer,
            is_truncated,
            is_recursion_desired,
            is_recursion_available,
            response_code,
        };
    }
}

macro_rules! bit_subset {
    ($($t:ty),* => $f:item) => {$(
        impl BitSubset for $t {
            $f
        }
    )*};
}

bit_subset! {
    i8,i16,i32,i64,i128,u8,u16,u32,u64,u128 =>
        fn bit_subset(&self, from_bit: usize, count: u32) -> Self {
        let mask = (1 << count) - 1;
        (self >> from_bit) & mask
    }
}

pub fn encode_label(label: &str) -> Vec<u8> {
    let mut encoded: Vec<u8> = vec![];
    &for x in label.split(".") {
        encoded.push(x.len() as u8);
        encoded.extend_from_slice(x.as_bytes());
    };
    encoded.push(0); // Indicating the end of the label.
    return encoded;
}

pub fn read_label(buffer: &mut ByteReader) -> String {
    let mut characters: Vec<u8> = vec![];
    let mut return_to: usize = 0;
    loop {
        let byte = buffer.read().unwrap();
        if byte == 0 {
            break;
        }
        let is_pointer = byte >= 0b11000000;
        if is_pointer {
            let byte = byte as usize;
            let next_byte = buffer.read().unwrap() as usize;
            let shifted = (byte & 0b00111111) << 8;
            let position = shifted | next_byte;
            let jump_position = position;
            if return_to == 0 {
                return_to = buffer.position
            }
            buffer.jump_to(jump_position);
        } else {
            let label_length = byte as usize;
            let min = min(label_length, buffer.remaining_bytes());
            let label_slice = buffer.read_multiple(min).unwrap();
            if (label_length != min) {
                println!("Label length: {}, {:08b}", label_length, label_length as u8);
                println!("Missmatch and will be error: {}", String::from_utf8_lossy(label_slice));
                println!("Missmatch and will be error: {}", String::from_utf8_lossy(buffer.buffer));
                panic!("STOP");
            }
            if !characters.is_empty() {
                characters.extend_from_slice(".".as_bytes()); // Add dot
            }
            characters.extend_from_slice(label_slice);
        }
        if !buffer.has_remaining() {
            break;
        }
    }
    if return_to > 0 {
        buffer.jump_to(return_to);
    }
    return String::from_utf8(characters).unwrap();
}

fn read_record_information(buffer: &mut ByteReader) -> RecordInformation {
    let label = read_label(buffer);
    let record_type = buffer.read_u16::<BigEndian>().unwrap(); // Get Into ENUM value somehow
    let flags = buffer.read_u16::<BigEndian>().unwrap();
    let class_code = flags & (0xFFFF - 1);
    let has_property = flags.bit_subset(15, 1) == 1;
    return RecordInformation {
        label,
        record_type: RecordType::from(record_type),
        flags,
        class_code,
        has_property,
    };
}

fn read_complete_record(buffer: &mut ByteReader, discard_data: bool) -> CompleteRecord {
    let record_information = read_record_information(buffer);
    let ttl = buffer.read_u32::<BigEndian>().unwrap();
    let data_length = buffer.read_u16::<BigEndian>().unwrap() as usize;
    let mut data: Vec<u8> = vec![];
    if discard_data {
        buffer.jump_to(buffer.position + data_length)
    } else {
        buffer.copy_into(&mut data);
    }
    return CompleteRecord {
        record_information,
        ttl,
        data,
    };
}
