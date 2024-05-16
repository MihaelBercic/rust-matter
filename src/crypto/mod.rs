use hmac::{Hmac, Mac};
use hmac::digest::MacError;
use p256::ecdh::EphemeralSecret;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::ecdsa::signature::Signer;
use p256::elliptic_curve::rand_core::OsRng;
use p256::PublicKey;
use rand::{Rng, thread_rng};
use sha2::{Digest, Sha256};

use crate::crypto::constants::CRYPTO_GROUP_SIZE_BYTES;

pub mod constants;
pub mod kdf;
pub mod s2p_test_vectors;
pub mod spake;
pub mod symmetric;

type HmacSha256 = Hmac<Sha256>;

pub struct KeyPair {
    pub private_key: SigningKey,
    pub public_key: VerifyingKey,
}

pub struct EccKeyPair {
    pub private_key: EphemeralSecret,
    pub public_key: PublicKey,
}

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
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes any key size");
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

/// ECDSA - Generates a Public - Private key pair using NIST-P256
pub fn generate_key_pair() -> KeyPair {
    let private_key = SigningKey::random(&mut OsRng);
    let public_key = VerifyingKey::from(&private_key);
    KeyPair {
        private_key,
        public_key,
    }
}

/// ECDH - Generates a Public - Private key pair using NIST-P256
pub fn ecc_generate_key_pair() -> EccKeyPair {
    let private_key = EphemeralSecret::random(&mut OsRng);
    let public_key = private_key.public_key();
    EccKeyPair {
        private_key,
        public_key,
    }
}

/// Signs a message using the [key] into signature which is of length [2 * CRYPTO_GROUP_SIZE_BYTES]
/// TODO: Check in case of BigEndian errors
pub fn sign_message(key: &SigningKey, message: &[u8]) -> [u8; 2 * CRYPTO_GROUP_SIZE_BYTES] {
    let signed: Signature = key.sign(message);
    let mut signature_bytes = [0u8; 2 * CRYPTO_GROUP_SIZE_BYTES];
    signature_bytes.copy_from_slice(&signed.to_bytes()[..]);
    signature_bytes
}

/// Computes ECDH shared secret using [ecdh]
pub fn ecdh(private_key: EphemeralSecret, public_key: &[u8]) -> [u8; CRYPTO_GROUP_SIZE_BYTES] {
    let their_public = PublicKey::from_sec1_bytes(public_key).expect("Invalid public key.");
    let shared = private_key.diffie_hellman(&their_public);
    let mut bytes = [0u8; CRYPTO_GROUP_SIZE_BYTES];
    bytes.copy_from_slice(&shared.raw_secret_bytes()[..]);
    bytes
}

/// Computes [N] random bytes and stores them in a vector.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut array = [0u8; N];
    let mut rng = thread_rng();
    for i in 0..N {
        array[i] = rng.gen_range(0..255)
    }
    return array;
}


pub fn random_bits(len: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    let mut bytes: Vec<u8> = vec![];
    let mut current = 0u8;
    for i in 1..=len {
        current |= if rng.gen_bool(0.5) { 1 } else { 0 };
        if i % 8 == 0 || i == len {
            bytes.insert(0, current);
            current = 0;
        } else {
            current <<= 1;
        }
    }
    return bytes;
}