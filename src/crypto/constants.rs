#![allow(non_snake_case, non_upper_case_globals)]
use crypto_bigint::U256;

pub const CRYPTO_GROUP_SIZE_BITS: usize = 256;
pub const CRYPTO_GROUP_SIZE_BYTES: usize = 32;
pub const CRYPTO_PUBLIC_KEY_SIZE_BYTES: usize = 65;

pub const CRYPTO_SYMMETRIC_KEY_LENGTH_BITS: usize = 128;
pub const CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES: usize = 16;
pub const CRYPTO_AEAD_MIC_LENGTH_BITS: usize = 128;
pub const CRYPTO_AEAD_MIC_LENGTH_BYTES: usize = 16;
pub const CRYPTO_AEAD_NONCE_LENGTH_BYTES: usize = 13;
pub const CRYPTO_PRIVACY_NONCE_LENGTH_BYTES: usize = 13;
pub const CRYPTO_HASH_LEN_BYTES: usize = 32;

pub const CRYPTO_PBKDF_ITERATIONS_MIN: u32 = 1000;
pub const CRYPTO_PBKDF_ITERATIONS_MAX: u32 = 100000;

pub const CRYPTO_W_SIZE_BYTES: usize = CRYPTO_GROUP_SIZE_BYTES + 8;
pub const CRYPTO_W_SIZE_BITS: usize = CRYPTO_W_SIZE_BYTES * 8;

/// const M: &str = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f";
pub static CRYPTO_M_BYTES: [u8; 33] = [
    0x2, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2, 0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab,
    0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f,
];

/// "CHIP PAKE V1 Commissioning" - The usage of CHIP here is intentional and due to implementation in the SDK before the name change, should not be renamed to Matter.
pub static CONTEXT_PREFIX_VALUE: [u8; 26] = [
    0x43, 0x48, 0x49, 0x50, 0x20, 0x50, 0x41, 0x4b, 0x45, 0x20, 0x56, 0x31, 0x20, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x69,
    0x6e, 0x67,
];

/// const N: &str = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49";
pub static CRYPTO_N_BYTES: [u8; 33] = [
    0x3, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77, 0x7, 0x19, 0xc6, 0x29, 0xd7, 0x1, 0x4d, 0x49,
    0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49,
];

pub static NIST_P_256_p_BYTES: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];
pub static NIST_P_256_n_BYTES: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

pub static NIST_P_256_n: U256 = U256::from_be_slice(&NIST_P_256_n_BYTES);
pub static NIST_P_256_p: U256 = U256::from_be_slice(&NIST_P_256_p_BYTES);

pub static CRYPTO_SESSION_KEYS_INFO: [u8; 11] = [0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x4b, 0x65, 0x79, 0x73];
