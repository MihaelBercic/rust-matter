use aes::Aes128;
use aes::cipher::typenum::U16;
use ccm::{
    Ccm,
    consts::U13,
};
use ccm::aead::{Aead, generic_array::GenericArray, KeyInit, Payload};

const CRYPTO_SYMMETRIC_KEY_LENGTH_BITS: usize = 128;
const CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES: usize = 16;
const CRYPTO_AEAD_MIC_LENGTH_BITS: usize = 128;
const CRYPTO_AEAD_MIC_LENGTH_BYTES: usize = 16;
const CRYPTO_AEAD_NONCE_LENGTH_BYTES: usize = 13;
const Q: usize = 2;
const N: usize = CRYPTO_AEAD_NONCE_LENGTH_BYTES;

pub fn encrypt_in_place<'a>(
    key: &[u8],
    payload: Payload,
    nonce: &[u8; CRYPTO_AEAD_NONCE_LENGTH_BYTES],
) -> Vec<u8> {
    type Cipher = Ccm<Aes128, U16, U13>;
    let cipher = Cipher::new_from_slice(key).unwrap();
    let nonce = GenericArray::from_slice(nonce);
    let encrypted = cipher.encrypt(&nonce, payload).expect("Unable to encrypt.");
    encrypted
}

pub fn decrypt(
    key: &[u8],
    encrypted_payload: Payload,
    nonce: &[u8; CRYPTO_AEAD_NONCE_LENGTH_BYTES],
) -> Vec<u8> {
    type Cipher = Ccm<Aes128, U16, U13>;
    let cipher = Cipher::new_from_slice(key).expect("Issue decrypting AES key.");
    let nonce = GenericArray::from_slice(nonce);
    let decrypted = cipher.decrypt(nonce, encrypted_payload).expect("Issue decrypting message");
    decrypted
}
