use std::ops::Rem;

use num_bigint::BigUint;

use crate::crypto::constants::{CRYPTO_GROUP_SIZE_BYTES, CRYPTO_W_SIZE_BITS, CRYPTO_W_SIZE_BYTES, NIST_P_256_ORDER};
use crate::crypto::kdf;
use crate::crypto::spake::values_initiator::ValuesInitiator;

///
/// @author Mihael Berčič
/// @date 7. 8. 24
///
pub mod values_initiator;


pub fn compute_values_initiator(passcode: &[u8], salt: &[u8], iterations: u32) -> ValuesInitiator {
    /*
    byte w0s[CRYPTO_W_SIZE_BYTES] || byte w1s[CRYPTO_W_SIZE_BYTES] = (byte[2 * CRYPTO_W_SIZE_BYTES])  bit[2 * CRYPTO_W_SIZE_BITS] Crypto_PBKDF(passcode, salt, iterations, 2 * CRYPTO_W_SIZE_BITS)
    byte w0[CRYPTO_GROUP_SIZE_BYTES] = w0s mod p
    byte w1[CRYPTO_GROUP_SIZE_BYTES] = w1s mod p
    */
    let pbkdf = kdf::password_key_derivation(passcode, salt, iterations, 2 * CRYPTO_W_SIZE_BITS);
    let mut w0s = [0u8; CRYPTO_W_SIZE_BYTES];
    let mut w1s = [0u8; CRYPTO_W_SIZE_BYTES];

    w0s.copy_from_slice(&pbkdf[0..CRYPTO_W_SIZE_BYTES]);
    w1s.copy_from_slice(&pbkdf[CRYPTO_W_SIZE_BYTES..]);
    let order: BigUint = BigUint::from_bytes_be(&NIST_P_256_ORDER);

    let w0 = BigUint::from_bytes_be(&w0s).rem(&order).to_bytes_be();
    let w1 = BigUint::from_bytes_be(&w1s).rem(&order).to_bytes_be();
    let mut w0_a = [0u8; CRYPTO_GROUP_SIZE_BYTES];
    let mut w1_a = [0u8; CRYPTO_GROUP_SIZE_BYTES];
    w0_a.copy_from_slice(&w0[0..CRYPTO_GROUP_SIZE_BYTES]);
    w1_a.copy_from_slice(&w1[0..CRYPTO_GROUP_SIZE_BYTES]);
    ValuesInitiator {
        w0: w0_a,
        w1: w1_a,
    }
}