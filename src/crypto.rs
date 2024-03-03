use hmac::{Hmac, Mac};
use hmac::digest::MacError;
use p256::elliptic_curve::rand_core;
use p256::SecretKey;
use rand_core::OsRng;
use sha2::{Digest, Sha256};

/**
Uses SHA-256 to hash the provided message.
 */
pub fn hash_message(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let result = hasher.finalize();
    let mut output_data: [u8; 32] = [0; 32];
    output_data.copy_from_slice(&result[..]);
    return output_data;
}

type HmacSha256 = Hmac<Sha256>;

/**
Generates a hash of the [message] with the provided [key];
 */
pub fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC should take any key size");
    mac.update(message);
    let result = mac.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result.into_bytes()[..]);
    return output;
}

/**
Verifies HMAC hash using the [key], [message] and [hashed message](code_bytes);
 */
pub fn verify_hmac(key: &[u8], message: &[u8], code_bytes: &[u8]) -> Result<(), MacError> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(message);
    return mac.verify_slice(&code_bytes[..]);
}

pub fn generate_key_pair() -> SecretKey {
    let secret = p256::SecretKey::random(&mut OsRng);
    return secret;
}