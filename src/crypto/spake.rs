use std::fmt::format;
use std::iter;
use crate::crypto::constants::{CRYPTO_GROUP_SIZE_BITS, CRYPTO_GROUP_SIZE_BYTES};
use crate::crypto::kdf;

#[allow(non_upper_case_globals)]
const M: &str = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f";
const N: &str = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49";

const CRYPTO_W_SIZE_BYTES: usize = CRYPTO_GROUP_SIZE_BYTES + 8;
const CRYPTO_W_SIZE_BITS: usize = CRYPTO_W_SIZE_BYTES * 8;

/// Passcode is serialized as **little endian** <br>
/// 18924017 = f1:c1:20:01 <br>
/// 00000005 = 05:00:00:00
pub fn compute_values_initiator(passcode: &[u8], salt: &[u8], iterations: u32) {
    const P: u32 = CRYPTO_GROUP_SIZE_BITS as u32;
    /*
    byte w0s[CRYPTO_W_SIZE_BYTES] || byte w1s[CRYPTO_W_SIZE_BYTES] =
        (byte[2 * CRYPTO_W_SIZE_BYTES])  bit[2 * CRYPTO_W_SIZE_BITS]
    Crypto_PBKDF(passcode, salt, iterations, 2 * CRYPTO_W_SIZE_BITS)
    */
    let mut computed: Vec<u8> = iter::repeat(0u8).take(2 * CRYPTO_W_SIZE_BYTES).collect();
    let pbkdf = kdf::password_key_derivation(passcode, salt, iterations, 2 * CRYPTO_W_SIZE_BITS);
    let mut w0s = [0u8; CRYPTO_W_SIZE_BYTES];
    let mut w1s = [0u8; CRYPTO_W_SIZE_BYTES];
    w0s.copy_from_slice(&pbkdf[0..CRYPTO_W_SIZE_BYTES]);
    w1s.copy_from_slice(&pbkdf[CRYPTO_W_SIZE_BYTES..]);
    println!("{}", hex::encode(w0s));
    println!("{}", hex::encode(w1s));
    // println!("w1: {}", w1);
}