use crate::utils::MatterLayer::{Parsing, Transport};
use std::any::Any;
use std::error::Error;
use std::fmt;
use std::io;
use std::time::SystemTimeError;

pub mod bit_subset;
pub mod byte_encodable;
pub mod padding;

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

impl fmt::Display for MatterError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MatterError::Custom(_layer, msg) => write!(f, "{:?}", msg),
            MatterError::Io(err) => write!(f, "IO Error: {:?}", err),
        }
    }
}

impl std::error::Error for MatterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            MatterError::Custom(_, _) => None,
            MatterError::Io(ref err) => Some(err),
        }
    }
}

impl From<io::Error> for MatterError {
    fn from(err: io::Error) -> MatterError {
        MatterError::Io(err)
    }
}

impl From<Vec<u8>> for MatterError {
    fn from(value: Vec<u8>) -> Self {
        MatterError::new(Parsing, "Unable to perform vector try_into.")
    }
}

impl From<SystemTimeError> for MatterError {
    fn from(value: SystemTimeError) -> Self {
        MatterError::new(Parsing, "Unable to parse SystemTime.")
    }
}
pub fn transport_error(msg: &str) -> MatterError {
    MatterError::new(Transport, msg)
}

pub fn generic_error(msg: &str) -> MatterError {
    MatterError::new(MatterLayer::Generic, msg)
}

pub fn crypto_error(msg: &str) -> MatterError {
    MatterError::new(MatterLayer::Cryptography, msg)
}

pub fn session_error(msg: &str) -> MatterError {
    MatterError::new(MatterLayer::SecureSession, msg)
}

