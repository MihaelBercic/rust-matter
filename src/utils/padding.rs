use std::cmp::max;
use std::iter;

///
/// @author Mihael Berčič
/// @date 17. 8. 24
///

pub enum PaddingMode {
    Left,
    Right,
}

pub trait Extensions {
    fn pad(&self, mode: PaddingMode, size: usize, value: u8) -> Vec<u8>;
}

impl Extensions for [u8] {
    fn pad(&self, mode: PaddingMode, size: usize, value: u8) -> Vec<u8> {
        let mut vector: Vec<u8> = vec![];
        let length = self.len();
        let padding_needed = max(size - length, 0);
        let adding: Vec<u8> = iter::repeat(value).take(padding_needed).collect();
        match mode {
            PaddingMode::Left => {
                vector.extend(&adding);
                vector.extend_from_slice(&self);
            }
            PaddingMode::Right => {
                vector.extend_from_slice(&self);
                vector.extend(&adding);
            }
        }
        return vector;
    }
}

pub trait StringExtensions {
    fn pad(self, mode: PaddingMode, size: usize, value: char) -> String;
}

// TODO: optimise this
impl StringExtensions for String {
    fn pad(self, mode: PaddingMode, size: usize, value: char) -> String {
        if self.len() >= size { return self; }
        let missing = size - self.len();
        let mut new_string = String::new();
        for i in 0..missing { new_string.push(value) }
        new_string.push_str(&self);
        new_string
    }
}