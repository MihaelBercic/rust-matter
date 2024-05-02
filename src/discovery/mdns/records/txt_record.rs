use std::collections::HashMap;

use byteorder::{BigEndian, WriteBytesExt};

pub struct TXTRecord {
    pub map: HashMap<String, String>,
}

impl Into<Vec<u8>> for TXTRecord {
    fn into(self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![];
        let pairs: Vec<String> = self.map.iter().map(|(a, b)| format!("{}={}", a, b)).collect();
        let total_length: usize = pairs.len() + pairs.iter().map(|x| x.len()).sum::<usize>();
        buffer.write_u16::<BigEndian>(total_length as u16).unwrap();
        for pair in pairs {
            buffer.push(pair.len() as u8);
            buffer.extend(pair.as_bytes());
        }
        println!("{}", buffer.iter().map(|x| format!("{:02x}", x)).collect::<Vec<String>>().join(" "));
        return buffer;
    }
}

/*
        val dataLength = dataMap.size + dataMap.toString().replace(cleanupRegex, "").length
        buffer.putShort(dataLength.toShort())
        dataMap.forEach { (key, value) ->
            val string = "$key=$value"
            val length = string.length
            buffer.put((length and 255).toByte())
            buffer.put(string.toByteArray())
        }
 */