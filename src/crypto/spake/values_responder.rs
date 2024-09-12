use crate::crypto::constants::{CRYPTO_GROUP_SIZE_BYTES, CRYPTO_PUBLIC_KEY_SIZE_BYTES};

///
/// @author Mihael Berčič
/// @date 8. 8. 24
/// Also referred to as Commissionee PAKE input or Verification Value.
#[allow(non_snake_case)]
#[derive(Debug, Clone)]
pub struct VerifierValues {
    pub w0: [u8; CRYPTO_GROUP_SIZE_BYTES],
    pub L: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
}