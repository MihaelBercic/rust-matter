use std::fmt;
use std::io;

pub mod bit_subset;
mod byte_encodable;

#[derive(Debug)]
pub enum MatterLayer {
    Transport,
    Application,
    Data,
    Interaction,
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
            MatterError::Custom(_layer, msg) => write!(f, "{}", msg),
            MatterError::Io(err) => write!(f, "IO Error: {}", err),
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