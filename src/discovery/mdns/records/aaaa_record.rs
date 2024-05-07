use std::net::Ipv6Addr;

use byteorder::{BigEndian, WriteBytesExt};

use crate::discovery::mdns::records::AAAARecord;

impl Into<Vec<u8>> for AAAARecord {
    fn into(self) -> Vec<u8> {
        let ip = self.address.parse::<Ipv6Addr>().expect("Unable to parse IPv6 address...");
        let mut buffer: Vec<u8> = vec![];
        buffer.write_u16::<BigEndian>(16).unwrap();
        buffer.extend_from_slice(&ip.octets());
        println!("{}", buffer.iter().map(|x| format!("0x{:02x}", x)).collect::<Vec<String>>().join(" "));
        return buffer;
    }
}