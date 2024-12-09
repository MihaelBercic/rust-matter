use std::io;

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
