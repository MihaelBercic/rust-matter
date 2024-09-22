use std::net::{Ipv4Addr, Ipv6Addr};

use byteorder::{BigEndian, WriteBytesExt};

use crate::mdns::records::{AAAARecord, ARecord};

impl Into<Vec<u8>> for AAAARecord {
    fn into(self) -> Vec<u8> {
        let ip = self.address.parse::<Ipv6Addr>().expect("Unable to parse IPv6 address...");
        let mut buffer: Vec<u8> = vec![];
        buffer.write_u16::<BigEndian>(16).unwrap();
        buffer.extend_from_slice(&ip.octets());
        buffer
    }
}

impl Into<Vec<u8>> for ARecord {
    fn into(self) -> Vec<u8> {
        let ip = self.address.parse::<Ipv4Addr>().expect("Unable to parse IPv6 address...");
        let mut buffer: Vec<u8> = vec![];
        buffer.write_u16::<BigEndian>(4).unwrap();
        buffer.extend_from_slice(&ip.octets());
        buffer
    }
}