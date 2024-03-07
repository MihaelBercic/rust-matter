use aes::Aes128;
use ccm::{
    Ccm,
    consts::{U10, U13},
};
use ccm::aead::{AeadInPlace, generic_array::GenericArray, KeyInit};

const CRYPTO_SYMMETRIC_KEY_LENGTH_BITS: usize = 128;
const CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES: usize = 16;
const CRYPTO_AEAD_MIC_LENGTH_BITS: usize = 128;
const CRYPTO_AEAD_MIC_LENGTH_BYTES: usize = 16;
const CRYPTO_AEAD_NONCE_LENGTH_BYTES: usize = 13;
const Q: usize = 2;
const N: usize = CRYPTO_AEAD_NONCE_LENGTH_BYTES;

pub fn generate_and_encrypt(
    key: &[u8],
    payload: &[u8],
    data: &[u8],
    nonce: &[u8; CRYPTO_AEAD_NONCE_LENGTH_BYTES],
) -> Vec<u8> {
    /*
    byte[lengthInBytes(P) + CRYPTO_AEAD_MIC_LENGTH_BYTES]
    Crypto_AEAD_GenerateEncrypt(
         SymmetricKey K,
         byte[lengthInBytes(P)] P,
         byte[] A,
         byte[CRYPTO_AEAD_NONCE_LENGTH_BYTES] N)
    */
    type Cipher = Ccm<Aes128, U10, U13>;
    let key = GenericArray::from_slice(key);
    let nonce = GenericArray::from_slice(nonce);
    let cipher = Cipher::new(key);

    let mut buf1 = [0; u16::MAX as usize];
    let tag = cipher
        .encrypt_in_place_detached(nonce, data, &mut buf1)
        .expect("Issue encrypting.");

    let encrypted = &buf1[0..payload.len()];
    println!("Buffer data: {} for {} with tag {}", hex::encode(encrypted), String::from_utf8_lossy(payload), hex::encode(tag));
    tag.to_vec()
}
