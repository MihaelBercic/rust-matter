use crate::crypto::constants::CRYPTO_HASH_LEN_BYTES;

///
/// @author Mihael Berčič
/// @date 13. 9. 24
///

#[allow(non_snake_case)]
#[derive(Debug, Clone)]
pub struct SpakeConfirmation {
    pub c_a: [u8; CRYPTO_HASH_LEN_BYTES],
    pub cB: [u8; CRYPTO_HASH_LEN_BYTES],
    pub k_e: [u8; CRYPTO_HASH_LEN_BYTES / 2],
}


