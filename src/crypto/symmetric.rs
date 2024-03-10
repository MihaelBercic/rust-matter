use aes::{Aes128, Block};
use aes::cipher::BlockEncrypt;
use aes::cipher::typenum::U16;
use ccm::{Ccm, consts::U13, Error};
use ccm::aead::{Aead, generic_array::GenericArray, KeyInit, Payload};

const CRYPTO_SYMMETRIC_KEY_LENGTH_BITS: usize = 128;
const CRYPTO_AEAD_MIC_LENGTH_BITS: usize = 128;
const CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES: usize = 16;
const CRYPTO_AEAD_MIC_LENGTH_BYTES: usize = 16;
const CRYPTO_AEAD_NONCE_LENGTH_BYTES: usize = 13;
const CRYPTO_PRIVACY_NONCE_LENGTH_BYTES: usize = 13;
const Q: usize = 2;
const N: usize = CRYPTO_AEAD_NONCE_LENGTH_BYTES;

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
    message: &[u8],
    nonce: &[u8; CRYPTO_AEAD_NONCE_LENGTH_BYTES],
) {
    let cipher = Aes128::new_from_slice(key).expect("Issue parsing the key.");

    let chunks = message.chunks(16);
    for chunk in chunks {
        let mut block = Block::from([0u8; 16]);
        for (index, &value) in chunk.iter().enumerate() {
            block[index] = value;
        }
        println!("{}", hex::encode(block)) // store as block and encode later
    }

    return;

    let mut blocks = message.chunks(16).into_iter().map(|x| Block::from_slice(x));
    let block = Block::from_slice(&message[0..1]);
    println!("{}", hex::encode(block));
    // cipher.encrypt_blocks(&mut blocks);
}