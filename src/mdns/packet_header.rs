use crate::utils::BitSubset;

///
/// @author Mihael Berčič
/// @date 19. 6. 24
///
#[derive(Debug, Clone)]
pub struct MDNSPacketHeader {
    pub identification: u16,
    pub flags: u16,
}

impl From<MDNSPacketHeader> for [u8; 4] {
    fn from(value: MDNSPacketHeader) -> Self {
        let mut buf = [0u8; 4];
        let mut flags = 0u16;
        flags |= if value.is_response() { 1 } else { 0 };
        flags <<= 4;
        flags |= value.opcode() as u16;
        flags <<= 1;
        flags |= if value.is_authoritative_answer() { 1 } else { 0 };
        flags <<= 1;
        flags <<= 1;
        flags |= if value.is_recursion_desired() { 1 } else { 0 };
        flags <<= 8;

        let id_as_bytes: [u8; 2] = value.identification.to_be_bytes(); // identification is u16
        let flags_as_bytes: [u8; 2] = flags.to_be_bytes(); // flags is u16
        buf[0..2].copy_from_slice(&id_as_bytes);
        buf[2..4].copy_from_slice(&flags_as_bytes);
        buf
    }
}

impl MDNSPacketHeader {
    pub fn new(id: u16, flags: u16) -> Self {
        Self { identification: id, flags }
    }

    pub fn new_with_flags(id: u16, is_response: bool, opcode: u16, is_authoritative: bool, is_recursion_desired: bool) -> Self {
        let mut flags = 0u16;
        flags |= is_response as u16;
        flags <<= 4;
        flags |= opcode;
        flags <<= 1;
        flags |= is_authoritative as u16;
        flags <<= 1;
        flags <<= 1;
        flags |= is_recursion_desired as u16;
        flags <<= 8;
        Self { identification: id, flags }
    }

    pub fn is_response(&self) -> bool {
        self.flags.bit_subset(15, 1) == 1
    }

    pub fn opcode(&self) -> u8 {
        self.flags.bit_subset(11, 4) as u8
    }

    pub fn is_authoritative_answer(&self) -> bool {
        self.flags.bit_subset(10, 1) == 1
    }

    pub fn is_truncated(&self) -> bool {
        self.flags.bit_subset(9, 1) == 1
    }

    pub fn is_recursion_desired(&self) -> bool {
        self.flags.bit_subset(8, 1) == 1
    }

    pub fn is_recursion_available(&self) -> bool {
        self.flags.bit_subset(7, 1) == 1
    }

    pub fn response_code(&self) -> u8 {
        self.flags.bit_subset(0, 4) as u8
    }
}
