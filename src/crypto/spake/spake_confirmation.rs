use crate::crypto::constants::CRYPTO_HASH_LEN_BYTES;

///
/// @author Mihael Berčič
/// @date 13. 9. 24
///

#[allow(non_snake_case)]
#[derive(Debug)]
pub struct S2PConfirmation {
    pub cA: [u8; CRYPTO_HASH_LEN_BYTES],
    pub cB: [u8; CRYPTO_HASH_LEN_BYTES],
    pub Ke: [u8; CRYPTO_HASH_LEN_BYTES / 2],
}


