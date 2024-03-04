use hmac::digest::MacError;
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::rand_core::OsRng;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const CRYPTO_GROUP_SIZE_BITS: usize = 256;
const CRYPTO_GROUP_SIZE_BYTES: usize = 32;

/// Uses SHA-256 to hash the provided message.
pub fn hash_message(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let result = hasher.finalize();
    let mut output_data: [u8; 32] = [0; 32];
    output_data.copy_from_slice(&result[..]);
    output_data
}

/// Generates a hash of the [message] with the provided [key];
pub fn hmac(key: &[u8], message: &[u8]) -> [u8; CRYPTO_GROUP_SIZE_BYTES] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC should take any key size");
    mac.update(message);
    let result = mac.finalize();
    let mut output = [0u8; CRYPTO_GROUP_SIZE_BYTES];
    output.copy_from_slice(&result.into_bytes()[..]);
    output
}

/// Verifies HMAC hash using the [key], [message] and [hashed message](code_bytes);
pub fn verify_hmac(key: &[u8], message: &[u8], code_bytes: &[u8]) -> Result<(), MacError> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC should take any key size");
    mac.update(message);
    mac.verify_slice(&code_bytes[..])
}

/// Generates a Public - Private key pair using NIST-P256
pub fn generate_key_pair() -> SigningKey {
    SigningKey::random(&mut OsRng)
}

/// Signs a message using the [key] into signature which is of length [2 * CRYPTO_GROUP_SIZE_BYTES]
/// TODO: Check in case of BigEndian errors
pub fn sign_message(key: &SigningKey, message: &[u8]) -> [u8; 2 * CRYPTO_GROUP_SIZE_BYTES] {
    let signed: Signature = key.sign(message);
    let mut signature_bytes = [0u8; 2 * CRYPTO_GROUP_SIZE_BYTES];
    signature_bytes.copy_from_slice(&signed.to_bytes()[..]);
    signature_bytes
}
