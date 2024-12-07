use std::net::{Ipv4Addr, Ipv6Addr};

use byteorder::{WriteBytesExt, BE};

use crate::mdns::records::{AAAARecord, ARecord};

impl From<AAAARecord> for Vec<u8> {
    fn from(value: AAAARecord) -> Self {
        let ip = value.address.parse::<Ipv6Addr>().expect("Unable to parse IPv6 address...");
        let mut buffer: Vec<u8> = vec![];
        buffer.write_u16::<BE>(16).unwrap();
        buffer.extend_from_slice(&ip.octets());
        buffer
    }
}

impl From<ARecord> for Vec<u8> {
    fn from(value: ARecord) -> Self {
        let ip = value.address.parse::<Ipv4Addr>().expect("Unable to parse IPv6 address...");
        let mut buffer: Vec<u8> = vec![];
        buffer.write_u16::<BE>(4).unwrap();
        buffer.extend_from_slice(&ip.octets());
        buffer
    }
}
