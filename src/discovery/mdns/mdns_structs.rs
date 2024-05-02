use crate::discovery::mdns::mdns_structs::RecordType::{*, Unsupported};

#[derive(Debug)]
pub struct MDNSPacketHeader {
    pub identification: u16,
    pub flags: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub is_authoritative_answer: bool,
    pub is_truncated: bool,
    pub is_recursion_desired: bool,
    pub is_recursion_available: bool,
    pub response_code: u8,
}

#[allow(unused)]
pub struct MDNSPacket {
    pub header: MDNSPacketHeader,
    pub query_records: Vec<RecordInformation>,
    pub answer_records: Vec<CompleteRecord>,
    pub authority_records: Vec<CompleteRecord>,
    pub additional_records: Vec<CompleteRecord>,
}

#[derive(Debug)]
pub struct RecordInformation {
    pub label: String,
    pub record_type: RecordType,
    pub flags: u16,
    pub class_code: u16,
    pub has_property: bool,
}

#[derive(Debug)]
pub struct CompleteRecord {
    pub record_information: RecordInformation,
    pub ttl: u32,
    pub data: Vec<u8>,
}

#[repr(u16)]
#[derive(Debug)]
pub enum RecordType {
    Unsupported(u16) = 0,
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
    NSEC = 47,
}

impl From<u16> for RecordType {
    fn from(value: u16) -> Self {
        match value {
            1 => A,
            2 => NS,
            5 => CNAME,
            6 => SOA,
            12 => PTR,
            13 => HINFO,
            15 => MX,
            16 => TXT,
            17 => RP,
            18 => AFSDB,
            24 => SIG,
            25 => KEY,
            28 => AAAA,
            29 => LOC,
            33 => SRV,
            35 => NAPTR,
            36 => KX,
            37 => CERT,
            39 => DNAME,
            42 => APL,
            43 => DS,
            47 => NSEC,
            _ => Unsupported(value),
        }
    }
}

impl Into<u16> for RecordType {
    fn into(self) -> u16 {
        match self {
            A => 1,
            NS => 2,
            CNAME => 5,
            SOA => 6,
            PTR => 12,
            HINFO => 13,
            MX => 15,
            TXT => 16,
            RP => 17,
            AFSDB => 18,
            SIG => 24,
            KEY => 25,
            AAAA => 28,
            LOC => 29,
            SRV => 33,
            NAPTR => 35,
            KX => 36,
            CERT => 37,
            DNAME => 39,
            APL => 42,
            DS => 43,
            NSEC => 47,
            _ => 0,
        }
    }
}

pub trait BitSubset {
    fn bit_subset(&self, from_bit: usize, count: u32) -> Self;
}