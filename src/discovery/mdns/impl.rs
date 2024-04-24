use std::iter;

use byteorder::{BigEndian, ReadBytesExt};

use crate::discovery::mdns::mdns_structs::{
    BitSubset, CompleteRecord, MDNSPacket, MDNSPacketHeader, RecordInformation, RecordType,
};
use crate::useful::byte_reader::ByteReader;

impl Into<Vec<u8>> for RecordInformation {
    fn into(self) -> Vec<u8> {
        todo!()
    }
}

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
        println!("QC: {}", query_count);

        for _ in 0..query_count {
            let query_record = read_record_information(&mut byte_reader);
            println!("Query: {:?}", query_record);
        }

        for _ in 0..answer_count {
            let complete_record = read_complete_record(&mut byte_reader);
            println!("Answer {:?}", complete_record);
        }

        for _ in 0..authority_count {
            let complete_record = read_complete_record(&mut byte_reader);
            println!("Authority {:?}", complete_record);
        }

        for _ in 0..additional_count {
            let complete_record = read_complete_record(&mut byte_reader);
            println!("Additional {:?}", complete_record);
        }

        println!("Header: {:#?}", header);
        println!(
            "QC: {}, AnC: {}, AuC: {}, AdC: {}",
            query_count, answer_count, authority_count, additional_count
        );
        todo!("")
    }
}

impl Into<[u8; 4]> for MDNSPacketHeader {
    fn into(self) -> [u8; 4] {
        let mut buf = [0u8; 4];
        let id_as_bytes: [u8; 2] = self.identification.to_be_bytes(); // identification is u16
        let flags_as_bytes: [u8; 2] = self.flags.to_be_bytes(); // identification is u16
        buf[0..2].copy_from_slice(&id_as_bytes);
        buf[2..4].copy_from_slice(&flags_as_bytes);
        return buf;
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
            identification: 0,
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

fn read_label(buffer: &mut ByteReader) -> String {
    let mut characters: Vec<u8> = vec![];
    let mut return_to: usize = 0;
    loop {
        let byte = buffer.read().unwrap();
        if byte == 0 {
            break;
        }
        let is_pointer = byte >= 0b11000000;
        if is_pointer {
            let byte_as_usize = byte as usize;
            let next_byte = buffer.read().unwrap() as usize;
            let shifted = ((byte_as_usize & 0b00111111) << 8); // What's the point of this...
            let position = shifted | next_byte;
            let jump_position = position;
            if return_to == 0 {
                return_to = buffer.position
            }
            buffer.jump_to(jump_position);
        } else {
            let label_length = byte as usize;
            let label_slice = buffer.read_multiple(label_length).unwrap();
            if !characters.is_empty() {
                characters.extend_from_slice(".".as_bytes()); // Add dot
            }
            characters.extend_from_slice(label_slice);
        }
        if !buffer.has_remaining() {
            break;
        }
    }
    if (return_to > 0) {
        buffer.jump_to(return_to);
    }
    return String::from_utf8_lossy(&characters[..]).to_string();
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

fn read_complete_record(buffer: &mut ByteReader) -> CompleteRecord {
    let record_information = read_record_information(buffer);
    let ttl = buffer.read_u32::<BigEndian>().unwrap();
    let data_length = buffer.read_u16::<BigEndian>().unwrap();
    let mut data: Vec<u8> = iter::repeat(0u8).take(data_length as usize).collect();
    buffer.copy_into(&mut data);
    return CompleteRecord {
        record_information,
        ttl,
        data_length,
        data,
    };
}
