use std::io::{Cursor, Read};

use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use p256::pkcs8::der::Writer;

use crate::tlv::element_type::ElementType::*;
use crate::tlv::encodable_value::EncodableValue;
use crate::tlv::tlv::TLV;
use crate::utils::MatterError;
use crate::utils::MatterLayer::Application;

///
/// @author Mihael Berčič
/// @date 1. 8. 24
///
#[derive(Clone, Debug)]
pub enum ElementType {
    Signed8(i8),
    Signed16(i16),
    Signed32(i32),
    Signed64(i64),
    Unsigned8(u8),
    Unsigned16(u16),
    Unsigned32(u32),
    Unsigned64(u64),
    BooleanFalse,
    BooleanTrue,
    FloatingPoint4(f32),
    FloatingPoint8(f64),
    UTFString8(String),
    UTFString16(String),
    UTFString32(String),
    UTFString64(String),
    OctetString8(Vec<u8>),
    OctetString16(Vec<u8>),
    OctetString32(Vec<u8>),
    OctetString64(Vec<u8>),
    Null,
    Structure(Vec<TLV>),
    Array(Vec<TLV>),
    List(Vec<TLV>),
    EndOfContainer,
    Reserved,
}

impl ElementType {
    pub(crate) fn into_u64(self) -> Result<u64, MatterError> {
        match self {
            Unsigned64(value) => Ok(value),
            Unsigned32(value) => Ok(value as u64),
            Unsigned16(value) => Ok(value as u64),
            Unsigned8(value) => Ok(value as u64),
            _ => Err(MatterError::new(Application, "Not possible to be matched into u64...")),
        }
    }

    pub(crate) fn into_octet_string(self) -> Result<Vec<u8>, MatterError> {
        match self {
            OctetString8(value) => Ok(value),
            OctetString16(value) => Ok(value),
            OctetString32(value) => Ok(value),
            OctetString64(value) => Ok(value),
            _ => Err(MatterError::new(Application, "Not possible to be matched into string...")),
        }
    }

    pub(crate) fn into_string(self) -> Result<String, MatterError> {
        match self {
            UTFString8(value) => Ok(value),
            UTFString16(value) => Ok(value),
            UTFString32(value) => Ok(value),
            UTFString64(value) => Ok(value),
            _ => Err(MatterError::new(Application, "Not possible to be matched into string...")),
        }
    }

    pub(crate) fn into_u32(self) -> Result<u32, MatterError> {
        match self {
            Unsigned32(value) => Ok(value),
            Unsigned16(value) => Ok(value as u32),
            Unsigned8(value) => Ok(value as u32),
            _ => Err(MatterError::new(Application, "Not possible to be matched into u32...")),
        }
    }

    pub(crate) fn into_u8(self) -> Result<u8, MatterError> {
        match self {
            Unsigned8(value) => Ok(value),
            _ => Err(MatterError::new(Application, "Not possible to be matched into u32...")),
        }
    }

    pub(crate) fn into_u16(self) -> Result<u16, MatterError> {
        match self {
            Unsigned16(value) => Ok(value),
            Unsigned8(value) => Ok(value as u16),
            _ => Err(MatterError::new(Application, "Not possible to be matched into u16...")),
        }
    }

    pub(crate) fn into_boolean(self) -> Result<bool, MatterError> {
        match self {
            BooleanFalse => Ok(false),
            BooleanTrue => Ok(true),
            _ => Err(MatterError::new(Application, "Not possible to be matched into u16...")),
        }
    }

    fn read_children(cursor: &mut Cursor<&[u8]>) -> Vec<TLV> {
        let mut children: Vec<TLV> = vec![];
        while cursor.read_u8().unwrap() != EndOfContainer.into() {
            cursor.set_position(cursor.position() - 1);
            children.push(TLV::try_from_cursor(cursor).unwrap());
        }
        children
    }

    pub fn from_with_value(byte: u8, cursor: &mut Cursor<&[u8]>) -> Result<Self, MatterError> {
        let x = match byte {
            0 => Signed8(cursor.read_i8()?),
            1 => Signed16(cursor.read_i16::<LE>()?),
            2 => Signed32(cursor.read_i32::<LE>()?),
            3 => Signed64(cursor.read_i64::<LE>()?),
            4 => Unsigned8(cursor.read_u8()?),
            5 => Unsigned16(cursor.read_u16::<LE>()?),
            6 => Unsigned32(cursor.read_u32::<LE>()?),
            7 => Unsigned64(cursor.read_u64::<LE>()?),
            8 => BooleanFalse,
            9 => BooleanTrue,
            10 => FloatingPoint4(cursor.read_f32::<LE>()?),
            11 => FloatingPoint8(cursor.read_f64::<LE>()?),
            12 => {
                let length = cursor.read_u8()?;
                let mut data = vec![0u8; length as usize];
                cursor.read_exact(&mut data).expect("Unable to read UTF8 string...");
                UTFString8(String::from_utf8_lossy(&data).to_string())
            }
            13 => {
                let length = cursor.read_u16::<LE>()?;
                let mut data = vec![0u8; length as usize];
                cursor.read_exact(&mut data).expect("Unable to read UTF8 string...");
                UTFString16(String::from_utf8_lossy(&data).to_string())
            }
            14 => {
                let length = cursor.read_u32::<LE>()?;
                let mut data = vec![0u8; length as usize];
                cursor.read_exact(&mut data).expect("Unable to read UTF8 string...");
                UTFString32(String::from_utf8_lossy(&data).to_string())
            }
            15 => {
                let length = cursor.read_u64::<LE>()?;
                let mut data = vec![0u8; length as usize];
                cursor.read_exact(&mut data).expect("Unable to read UTF8 string...");
                UTFString64(String::from_utf8_lossy(&data).to_string())
            }
            16 => {
                let length = cursor.read_u8()?;
                let mut data = vec![0u8; length as usize];
                cursor.read_exact(&mut data).expect("Unable to read UTF8 string...");
                OctetString8(data)
            }
            17 => {
                let length = cursor.read_u16::<LE>()?;
                let mut data = vec![0u8; length as usize];
                cursor.read_exact(&mut data).expect("Unable to read UTF8 string...");
                OctetString16(data)
            }
            18 => {
                let length = cursor.read_u32::<LE>()?;
                let mut data = vec![0u8; length as usize];
                cursor.read_exact(&mut data).expect("Unable to read UTF8 string...");
                OctetString32(data)
            }
            19 => {
                let length = cursor.read_u64::<LE>()?;
                let mut data = vec![0u8; length as usize];
                cursor.read_exact(&mut data).expect("Unable to read UTF8 string...");
                OctetString64(data)
            }
            20 => Null,
            21 => Structure(Self::read_children(cursor)),
            22 => Array(Self::read_children(cursor)),
            23 => List(Self::read_children(cursor)),
            24 => EndOfContainer,
            _ => Reserved,
        };
        Ok(x)
    }

    pub fn data_length(byte: u8) -> usize {
        match byte {
            0 | 4 | 12 | 16 => 1,
            1 | 5 | 13 | 17 => 2,
            2 | 6 | 10 | 14 | 18 => 4,
            3 | 7 | 11 | 15 | 19 => 8,
            8 | 9 => 1,
            20 => 1,
            _ => 0,
        }
    }
}

impl From<ElementType> for u8 {
    fn from(value: ElementType) -> Self {
        match value {
            Signed8(_) => 0,
            Signed16(_) => 1,
            Signed32(_) => 2,
            Signed64(_) => 3,
            Unsigned8(_) => 4,
            Unsigned16(_) => 5,
            Unsigned32(_) => 6,
            Unsigned64(_) => 7,
            BooleanFalse => 8,
            BooleanTrue => 9,
            FloatingPoint4(_) => 10,
            FloatingPoint8(_) => 11,
            UTFString8(_) => 12,
            UTFString16(_) => 13,
            UTFString32(_) => 14,
            UTFString64(_) => 15,
            OctetString8(_) => 16,
            OctetString16(_) => 17,
            OctetString32(_) => 18,
            OctetString64(_) => 19,
            Null => 20,
            Structure(_) => 21,
            Array(_) => 22,
            List(_) => 23,
            EndOfContainer => 24,
            Reserved => 25,
        }
    }
}

impl From<ElementType> for Option<Vec<u8>> {
    fn from(value: ElementType) -> Self {
        match value {
            Signed8(value) => Some(value.to_bytes()),
            Signed16(value) => Some(value.to_bytes()),
            Signed32(value) => Some(value.to_bytes()),
            Signed64(value) => Some(value.to_bytes()),
            Unsigned8(value) => Some(value.to_bytes()),
            Unsigned16(value) => Some(value.to_bytes()),
            Unsigned32(value) => Some(value.to_bytes()),
            Unsigned64(value) => Some(value.to_bytes()),
            FloatingPoint4(value) => Some(value.to_bytes()),
            FloatingPoint8(value) => Some(value.to_bytes()),
            UTFString8(value) => Some(string_representation::<1>(value.as_bytes())),
            UTFString16(value) => Some(string_representation::<2>(value.as_bytes())),
            UTFString32(value) => Some(string_representation::<4>(value.as_bytes())),
            UTFString64(value) => Some(string_representation::<8>(value.as_bytes())),
            OctetString8(value) => Some(string_representation::<1>(&value)),
            OctetString16(value) => Some(string_representation::<2>(&value)),
            OctetString32(value) => Some(string_representation::<4>(&value)),
            OctetString64(value) => Some(string_representation::<8>(&value)),
            Null => None,
            Structure(values) => create_container(values),
            Array(values) => create_container(values),
            List(values) => create_container(values),
            EndOfContainer => None,
            Reserved => None,
            BooleanFalse => None,
            BooleanTrue => None,
        }
    }
}

impl From<Vec<u32>> for ElementType {
    fn from(value: Vec<u32>) -> Self {
        Array(value.into_iter().map(|x| TLV::simple(x.into())).collect())
    }
}

impl From<bool> for ElementType {
    fn from(value: bool) -> Self {
        if value {
            BooleanTrue
        } else {
            BooleanFalse
        }
    }
}

impl From<String> for ElementType {
    fn from(value: String) -> ElementType {
        let data = value.to_string();
        match data.len() {
            0..0xFF => UTFString8(data),
            0xFF..0xFF_FF => UTFString16(data),
            0xFF_FF..0xFF_FF_FF_FF => UTFString32(data),
            _ => UTFString64(data),
        }
    }
}

impl From<Vec<u8>> for ElementType {
    fn from(value: Vec<u8>) -> Self {
        let len = value.len() as u64;
        match len {
            0..=0xFF => OctetString8(value),
            0x100..=0xFF_FF => OctetString16(value),
            0x10000..=0xFF_FF_FF_FF => OctetString32(value),
            _ => OctetString64(value),
        }
    }
}

impl From<Vec<u16>> for ElementType {
    fn from(value: Vec<u16>) -> Self {
        Array(value.into_iter().map(|x| TLV::simple(x.into())).collect())
    }
}

impl<const C: usize> From<[u8; C]> for ElementType {
    fn from(value: [u8; C]) -> Self {
        let len = C as u64;
        match len {
            0..=0xFF => OctetString8(value.into()),
            0x100..=0xFF_FF => OctetString16(value.into()),
            0x10000..=0xFF_FF_FF_FF => OctetString32(value.into()),
            _ => OctetString64(value.into()),
        }
    }
}

fn create_container(values: Vec<TLV>) -> Option<Vec<u8>> {
    let mut bytes: Vec<u8> = vec![];
    for tlv in values {
        bytes.extend_from_slice(&tlv.to_bytes());
    }
    bytes.extend_from_slice(&TLV::simple(EndOfContainer).to_bytes());
    Some(bytes)
}

fn create_string_representation<T: LengthCollection>(value: T) -> Vec<u8> {
    combine_vectors(remove_trailing_zero_bytes(&mut value.len().to_le_bytes().to_vec()), &value.into_bytes())
}

fn string_representation<const C: usize>(string: &[u8]) -> Vec<u8> {
    let length = string.len();
    let mut data = vec![];
    match C {
        1 => data.write_byte(length as u8).expect("Unable to write string length..."),
        2 => data.write_u16::<LE>(length as u16).expect("Unable to write string length..."),
        4 => data.write_u32::<LE>(length as u32).expect("Unable to write string length..."),
        8 => data.write_u64::<LE>(length as u64).expect("Unable to write string length..."),
        _ => {}
    }
    data.extend_from_slice(string);
    data
}

fn combine_vectors(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut vec = vec![];
    vec.extend_from_slice(a);
    vec.extend_from_slice(b);
    vec
}

fn remove_trailing_zero_bytes(vec: &mut Vec<u8>) -> &mut Vec<u8> {
    for i in (0..vec.len()).rev() {
        let byte = vec[i];
        if byte == 0 {
            vec.remove(i);
            continue;
        }
        break;
    }
    vec
}

trait LengthCollection {
    fn len(&self) -> usize;
    fn into_bytes(self) -> Vec<u8>;
}

impl LengthCollection for String {
    fn len(&self) -> usize {
        self.len()
    }

    fn into_bytes(self) -> Vec<u8> {
        self.into_bytes()
    }
}

impl LengthCollection for Vec<u8> {
    fn len(&self) -> usize {
        self.len()
    }

    fn into_bytes(self) -> Vec<u8> {
        self
    }
}
