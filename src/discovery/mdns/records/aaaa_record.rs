use byteorder::{BigEndian, WriteBytesExt};

#[derive(Debug)]
pub struct AAAARecord {
    pub address: String,
}

impl Into<Vec<u8>> for AAAARecord {
    fn into(self) -> Vec<u8> {
        let mut buffer: Vec<u8> = vec![];
        // fdc3:de31:45b5:c843:14aa:95ef:2844:22e
        // fdc3:de31:45b5:c843:89:981b:33af:57d2
        let x: [u8; 16] = [0xfd, 0xc3, 0xde, 0x31, 0x45, 0xb5, 0xc8, 0x43, 0, 0x89, 0x98, 0x1b, 0x33, 0xaf, 0x57, 0xd2];
        buffer.write_u16::<BigEndian>(16).unwrap();
        buffer.extend_from_slice(&x);
        println!("{}", buffer.iter().map(|x| format!("{:02x}", x)).collect::<Vec<String>>().join(" "));

        return buffer;
    }
}