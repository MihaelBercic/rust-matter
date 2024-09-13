use crate::crypto::constants::CRYPTO_GROUP_SIZE_BYTES;

///
/// @author Mihael Berčič
/// @date 7. 8. 24

/// Also referred to as Commissioner PAKE input!
#[derive(Debug, Clone)]
pub struct ProverValues {
    pub w0: [u8; CRYPTO_GROUP_SIZE_BYTES],
    pub w1: [u8; CRYPTO_GROUP_SIZE_BYTES],
}