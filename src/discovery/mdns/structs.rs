use std::ops::RangeInclusive;

use crate::discovery::mdns::records::record_type::RecordType;

/// A trait which allows for individual bit inspection.
pub trait BitSubset {
    fn bit_subset(&self, from_bit: usize, count: u32) -> Self;

    fn set_bits(&mut self, range: RangeInclusive<Self>, value: Self) -> Self
    where
        Self: Sized;
}

#[allow(unused)]
#[derive(Debug)]
pub struct MDNSPacket {
    pub header: MDNSPacketHeader,
    pub query_records: Vec<RecordInformation>,
    pub answer_records: Vec<CompleteRecord>,
    pub authority_records: Vec<CompleteRecord>,
    pub additional_records: Vec<CompleteRecord>,
}

#[derive(Debug, Clone)]
pub struct MDNSPacketHeader {
    pub identification: u16,
    pub flags: u16,
}

#[derive(Debug, Clone)]
pub struct RecordInformation {
    pub label: String,
    pub record_type: RecordType,
    pub flags: u16,
    pub class_code: u16,
    pub has_property: bool,
}

#[derive(Debug, Clone)]
pub struct CompleteRecord {
    pub record_information: RecordInformation,
    pub ttl: u32,
    pub data: Vec<u8>,
}
