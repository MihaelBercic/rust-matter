use byteorder::{BigEndian, WriteBytesExt};

use crate::mdns::records::TXTRecord;

impl Into<Vec<u8>> for TXTRecord {
    /// Encodes (key, value) pairs into desired Key=Value strings and encodes them using the [length][data].
    fn into(self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![];
        let pairs: Vec<&str> = self.text.split("\n").collect();
        for x in &pairs {
            println!("{}", x);
        }
        let total_length: usize = pairs.len() + pairs.iter().map(|x| x.len()).sum::<usize>();
        buffer.write_u16::<BigEndian>(total_length as u16).unwrap();
        for pair in pairs {
            buffer.push(pair.len() as u8);
            buffer.extend(pair.as_bytes());
        }
        return buffer;
    }
}

//TODO: Remove debugging println!("{}", buffer.iter().map(|x| format!("{:02x}", x)).collect::<Vec<String>>().join(" "));