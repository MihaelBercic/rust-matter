use crate::mdns::records::TXTRecord;
use byteorder::{WriteBytesExt, BE};

impl Into<Vec<u8>> for TXTRecord<'static> {
    /// Encodes (key, value) pairs into desired Key=Value strings and encodes them using the [length][data].
    fn into(self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![];
        let mapped = self.pairs.iter().map(|(key, value)| format!("{}={}", key, value)).collect::<Vec<String>>();
        let total_length = (mapped.join("").len() + mapped.len()) as u16;
        buffer.write_u16::<BE>(total_length).unwrap();
        for value in mapped {
            // println!("Writing {} to TXT record buffer...", value);
            buffer.push(value.len() as u8);
            buffer.extend(value.as_bytes());
        }
        buffer
    }
}

//TODO: Remove debugging println!("{}", buffer.iter().map(|x| format!("{:02x}", x)).collect::<Vec<String>>().join(" "));