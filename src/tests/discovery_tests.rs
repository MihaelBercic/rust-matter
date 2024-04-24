use std::io::{BufReader, Read};

use byteorder::{BigEndian, ReadBytesExt};
use num_traits::ToPrimitive;

use crate::useful::byte_reader::ByteReader;

#[cfg(test)]
pub mod discovery_tests {
    use crate::discovery::constants::SAMPLE_PACKET;
    use crate::tests::discovery_tests::{BitSubset, MDNSPacketHeader};

    #[test]
    fn hello() {
        let slice = &SAMPLE_PACKET[..];
        let header = MDNSPacketHeader {
            identification: 255,
            flags: 0,
            is_response: false,
            opcode: 0,
            is_authoritative_answer: false,
            is_truncated: false,
            is_recursion_desired: false,
            is_recursion_available: false,
            response_code: 0,
        };
        let data: [u8; 4] = header.into();

        println!("Data: {}", data.map(|x| format!("{:08b}", x)).join(" "));
        // let mdns_packet = MDNSPacket::from(slice);
    }

    #[test]
    fn bit_subset() {
        let num = 0xFF; // 1111 1111 = 255
        let desired = 0xF; // 1111 = 15;
        assert_eq!(num.bit_subset(4, 4), desired);
    }
}

struct DataGram {
    data: &'static [u8],
}

struct MDNSPacketHeader {
    identification: u16,
    flags: u16,
    is_response: bool,
    opcode: u8,
    is_authoritative_answer: bool,
    is_truncated: bool,
    is_recursion_desired: bool,
    is_recursion_available: bool,
    response_code: u8,
}

struct MDNSPacket {
    header: MDNSPacketHeader,
    query_count: u16,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
    query_records: Vec<RecordInformation>,
    answer_records: Vec<CompleteRecord>,
}

struct RecordInformation {
    label: String,
    record_type: RecordType,
    class_code: u8,
    has_property: bool,
}

struct CompleteRecord {
    record_information: RecordInformation,
    ttl: u32,
    data_length: u16,
    data: &'static [u8],
}

impl Into<Vec<u8>> for RecordInformation {
    fn into(self) -> Vec<u8> {
        todo!()
    }
}

enum RecordType {
    Unsupported = -1,
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    HINFO = 13,
    MX = 15,
    TXT = 16,
    RP = 17,
    AFSDB = 18,
    SIG = 24,
    KEY = 25,
    AAAA = 28,
    LOC = 29,
    SRV = 33,
    NAPTR = 35,
    KX = 36,
    CERT = 37,
    DNAME = 39,
    APL = 42,
    DS = 43,
}

impl DataGram {
    fn read_label(&self) -> String {
        let mut buffer = ByteReader::new(self.data);
        let mut characters: Vec<u8> = vec![];
        let mut return_to: usize = 0;
        while buffer.has_remaining() {
            // Has remaining
            let byte = buffer.read().unwrap();
            let is_pointer = byte >= 0b11000000;
            if byte == 0 {
                break;
            }
            if is_pointer {
                let shifted: u16 = (byte & 0b00111111).to_u16().unwrap() << 8; // What's the point of this...
                let next_byte = buffer.read().unwrap().to_u16().unwrap();
                let jump_position = next_byte & 0xFF;
                println!("Jumping to {}", jump_position);
                if return_to == 0 {
                    return_to = buffer.position
                }
                buffer.jump_to(jump_position as usize);
            } else {
                let label_length = buffer.read().unwrap() as usize;
                let label_slice = buffer.read_multiple(label_length).unwrap();
                // if !characters.is_empty() { characters.push(0xB7) } // Add dot
                characters.extend_from_slice(label_slice);
            }
        }
        return String::from_utf8_lossy(&characters[..]).to_string();
    }
}

impl From<&[u8]> for MDNSPacket {
    fn from(value: &[u8]) -> Self {
        let mut r = BufReader::new(value);
        let id = r.read_u16::<BigEndian>().unwrap();
        let flags = r.read_u16::<BigEndian>().unwrap();

        /*
                val isResponse = flags.bits(15, 1) == 1
        val opcode = flags.bits(11, 4)
        val isAuthoritative = flags.bits(10, 1) == 1
        val isTruncated = flags.bits(9, 1) == 1
        val isRecursionDesired = flags.bits(8, 1) == 1
        val isRecursionAvailable = flags.bits(7, 1) == 1
        val responseCode = flags.bits(0, 4)
         */
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

trait BitSubset {
    fn bit_subset(&self, from_bit: usize, count: u32) -> Self;
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
