use crate::constants::{TEST_CMS_SIGNER_PRIVATE_KEY, TEST_CMS_SIGNER_SUBJECT_KEY_IDENTIFIER};
use crate::crypto::constants::{CRYPTO_GROUP_SIZE_BYTES, CRYPTO_HASH_LEN_BYTES};
use crate::mdns::enums::DeviceType;
use crate::session::protocol::interaction::cluster::CertificationDeclaration;
use crate::session::protocol::interaction::der::{
    DerCertificationDeclaration, DigestAlgorithmIdentifier, EncapsulatedContentInfo, Pkcs7SignedData, SignerInfo,
};
use crate::tlv::tlv::Tlv;
use der::asn1::{ContextSpecific, Int, OctetString, SetOf};
use der::TagMode::Implicit;
use der::{Encode, TagMode, TagNumber};
use hmac::digest::MacError;
use hmac::{Hmac, Mac};
use p256::ecdh::EphemeralSecret;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::signature::{SignatureEncoding, Signer};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::OsRng;
use p256::{NistP256, PublicKey};
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};
use signature::Keypair;
use std::str::FromStr;

pub mod constants;
pub mod kdf;
pub mod spake;
pub mod symmetric;

type HmacSha256 = Hmac<Sha256>;

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
pub fn hmac(key: &[u8], message: &[u8]) -> [u8; CRYPTO_HASH_LEN_BYTES] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes any key size");
    mac.update(message);
    let result = mac.finalize();
    result.into_bytes().try_into().unwrap()
}

/// Verifies HMAC hash using the [key], [message] and [hashed message](code_bytes);
pub fn verify_hmac(key: &[u8], message: &[u8], code_bytes: &[u8]) -> Result<(), MacError> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC should take any key size");
    mac.update(message);
    mac.verify_slice(&code_bytes[..])
}

/// ECDSA - Generates a Public - Private key pair using NIST-P256
pub fn generate_key_pair() -> ecdsa::SigningKey<NistP256> {
    ecdsa::SigningKey::random(&mut OsRng)
}

/// ECDH - Generates a Public - Private key pair using NIST-P256
pub fn ecc_generate_key_pair() -> EccKeyPair {
    let private_key = EphemeralSecret::random(&mut OsRng);
    let public_key = private_key.public_key();
    EccKeyPair { private_key, public_key }
}

/// Signs a message using the [key] into signature which is of length [2 * CRYPTO_GROUP_SIZE_BYTES]
/// TODO: Check in case of BigEndian errors
pub fn sign_message(key: &SigningKey, message: &[u8]) -> [u8; 2 * CRYPTO_GROUP_SIZE_BYTES] {
    let signed: Signature = key.sign(message);
    let mut signature_bytes = [0u8; 2 * CRYPTO_GROUP_SIZE_BYTES];
    signature_bytes.copy_from_slice(&signed.to_bytes()[..]);
    signature_bytes
}

/// Signs a message using the [key] into signature which is of length [2 * CRYPTO_GROUP_SIZE_BYTES]
/// TODO: Check in case of BigEndian errors
pub fn sign_message_with_signature(key: &SigningKey, message: &[u8]) -> Signature {
    key.sign(message)
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
    array
}

/// Compute random [len] bits.
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
    bytes
}
