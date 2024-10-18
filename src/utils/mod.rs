use crate::utils::MatterLayer::{Parsing, Transport};
use std::any::Any;
use std::error::Error;
use std::fmt;
use std::io;
use std::time::SystemTimeError;

mod bit_subset;
mod byte_encodable;
mod padding;
pub use bit_subset::BitSubset;
pub use byte_encodable::ByteEncodable;
pub use padding::*;

#[derive(Debug)]
pub enum MatterLayer {
    Cryptography,
    SecureSession,
    Parsing,
    Transport,
    Application,
    Data,
    Interaction,
    Generic,
    TLV,
}

#[derive(Debug)]
pub enum MatterError {
    Custom(MatterLayer, String),
    Io(io::Error),
}

impl MatterError {
    pub fn new(layer: MatterLayer, msg: &str) -> MatterError {
        MatterError::Custom(layer, msg.to_string())
    }
}

/// Implement the debugging trait for MatterError.
impl fmt::Display for MatterError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MatterError::Custom(_layer, msg) => write!(f, "{:?}", msg),
            MatterError::Io(err) => write!(f, "IO Error: {:?}", err),
        }
    }
}

/// Generate a MatterError from the std::Error::Error.
impl std::error::Error for MatterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            MatterError::Custom(_, _) => None,
            MatterError::Io(ref err) => Some(err),
        }
    }
}

/// Generate a MatterError from the built in io::Error.
impl From<io::Error> for MatterError {
    fn from(err: io::Error) -> MatterError {
        MatterError::Io(err)
    }
}

/// Generate a MatterError from the failed attempt of TryFrom<Vec<u8>> for whatever the attempt was.
impl From<Vec<u8>> for MatterError {
    fn from(value: Vec<u8>) -> Self {
        MatterError::new(Parsing, "Unable to perform vector try_into.")
    }
}

/// Generate MatterError from the SystemTimeError for ease of use when returning Result.
impl From<SystemTimeError> for MatterError {
    fn from(value: SystemTimeError) -> Self {
        MatterError::new(Parsing, "Unable to parse SystemTime.")
    }
}

/// Generate a MatterError with [MatterLayer::Transport] layer.
pub fn transport_error(msg: &str) -> MatterError {
    MatterError::new(Transport, msg)
}

/// Generate a MatterError with a generic layer.
pub fn generic_error(msg: &str) -> MatterError {
    MatterError::new(MatterLayer::Generic, msg)
}

/// Generate a MatterError with TLV encoding layer.
pub fn tlv_error(msg: &str) -> MatterError {
    MatterError::new(MatterLayer::TLV, msg)
}

/// Generate a MatterError with Cryptography layer.
pub fn crypto_error(msg: &str) -> MatterError {
    MatterError::new(MatterLayer::Cryptography, msg)
}

/// Generate a MatterError with Session layer.
pub fn session_error(msg: &str) -> MatterError {
    MatterError::new(MatterLayer::SecureSession, msg)
}
