pub const CRYPTO_GROUP_SIZE_BITS: usize = 256;
pub const CRYPTO_GROUP_SIZE_BYTES: usize = 32;
pub const CRYPTO_PUBLIC_KEY_SIZE_BYTES: usize = 65;

pub const CRYPTO_SYMMETRIC_KEY_LENGTH_BITS: usize = 128;
pub const CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES: usize = 16;
pub const CRYPTO_AEAD_MIC_LENGTH_BITS: usize = 128;
pub const CRYPTO_AEAD_MIC_LENGTH_BYTES: usize = 16;
pub const CRYPTO_AEAD_NONCE_LENGTH_BYTES: usize = 13;
pub const CRYPTO_PRIVACY_NONCE_LENGTH_BYTES: usize = 13;

pub const Q: usize = 2;
pub const N: usize = CRYPTO_AEAD_NONCE_LENGTH_BYTES;

pub const CRYPTO_PBKDF_ITERATIONS_MIN: usize = 1000;
pub const CRYPTO_PBKDF_ITERATIONS_MAX: usize = 100000;
