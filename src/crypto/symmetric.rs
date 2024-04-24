use aes::Aes128;
use ccm::{Ccm, Error, KeyInit};
use ccm::aead::{Aead, Payload};
use ccm::aead::generic_array::GenericArray;
use ccm::consts::{U13, U16};
use ctr::cipher::{KeyIvInit, StreamCipher};

use crate::crypto::constants::{CRYPTO_AEAD_NONCE_LENGTH_BYTES, CRYPTO_PRIVACY_NONCE_LENGTH_BYTES};

pub fn encrypt<'a>(
    key: &[u8],
    payload: Payload,
    nonce: &[u8; CRYPTO_AEAD_NONCE_LENGTH_BYTES],
) -> Result<Vec<u8>, Error> {
    type Cipher = Ccm<Aes128, U16, U13>;
    let cipher = Cipher::new_from_slice(key).unwrap();
    let nonce = GenericArray::from_slice(nonce);
    let encrypted = cipher.encrypt(&nonce, payload);
    encrypted
}

pub fn decrypt(
    key: &[u8],
    encrypted_payload: Payload,
    nonce: &[u8; CRYPTO_AEAD_NONCE_LENGTH_BYTES],
) -> Result<Vec<u8>, Error> {
    type Cipher = Ccm<Aes128, U16, U13>;
    let cipher = Cipher::new_from_slice(key).expect("Issue decrypting AES key.");
    let nonce = GenericArray::from_slice(nonce);
    let decrypted = cipher.decrypt(nonce, encrypted_payload);
    decrypted
}

pub fn encrypt_ctr(
    key: &[u8],
    buffer: &mut [u8],
    nonce: &[u8; CRYPTO_PRIVACY_NONCE_LENGTH_BYTES],
) {
    type Aes128Ctr32LE = ctr::Ctr32LE<aes::Aes128>;
    let mut vec = nonce.to_vec();
    vec.push(0);
    vec.push(0);
    vec.push(0);
    let mut cipher = Aes128Ctr32LE::new_from_slices(key, &vec[..]).expect("Unable to create cipher from slices.");
    cipher.apply_keystream(buffer);
}

pub fn decrypt_ctr(
    key: &[u8],
    buffer: &mut [u8],
    nonce: &[u8; CRYPTO_PRIVACY_NONCE_LENGTH_BYTES],
) {
    type Aes128Ctr32LE = ctr::Ctr32LE<aes::Aes128>;
    let mut vec = nonce.to_vec();
    vec.push(0);
    vec.push(0);
    vec.push(0);
    let mut cipher = Aes128Ctr32LE::new_from_slices(key, &vec[..]).expect("Unable to create cipher from slices.");
    cipher.apply_keystream(buffer);
}
