pub struct ByteReader<'a> {
    buffer: &'a [u8],
    pub(crate) position: usize,
}

impl<'a> ByteReader<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        return Self {
            buffer,
            position: 0,
        };
    }

    pub fn read(&mut self) -> Result<u8, &str> {
        if !self.has_remaining() {
            return Err("Out of bounds");
        }
        let byte = self.buffer[self.position];
        self.position += 1;
        return Ok(byte);
    }

    pub fn read_multiple(&mut self, length: usize) -> Result<&[u8], &str> {
        if self.remaining_bytes() < length {
            return Err("Out of bounds");
        }
        let slice = &self.buffer[self.position..(self.position + length)];
        self.position += length;
        return Ok(slice);
    }

    pub fn read_into<const L: usize>(&mut self) -> Result<[u8; L], &str> {
        if self.remaining_bytes() < L {
            return Err("Out of bounds");
        }
        let mut buf = [0u8; L];
        let slice = &self.buffer[self.position..(self.position + L)];
        buf.copy_from_slice(slice);
        self.position += L;
        return Ok(buf);
    }

    pub fn copy_into(&self, dst: &mut [u8]) {
        dst.copy_from_slice(&self.buffer);
    }

    pub fn has_remaining(&self) -> bool {
        return self.remaining_bytes() > 0;
    }

    pub fn remaining_bytes(&self) -> usize {
        println!("LEN: {} POS: {}", self.buffer.len(), self.position);
        return self.buffer.len() - self.position;
    }

    pub fn jump_to(&mut self, position: usize) {
        self.position = position;
    }
}
