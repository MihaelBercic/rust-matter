#![allow(unused)]

use p256::PublicKey;

///
/// @author Mihael Berčič
/// @date 19. 6. 24
///

pub enum MessageType {
    Data,
    Control,
}

pub enum EncryptionLevel {
    Unencrypted,
    Encrypted(PublicKey),
}

pub enum ExchangeRole {
    Intitator,
    Responder,
}