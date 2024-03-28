use std::iter;

use hkdf::Hkdf;
use sha2::Sha256;
use crate::crypto::verify_hmac;

///
/// Key derivation function based on Chapter 3.8
///
/// Crypto_KDF(inputKey, salt, info, len) := bit[len] HKDF-Expand(PRK := HKDF-Extract(salt := salt, IKM := inputKey), info := info, L := (len / 8))
pub fn key_derivation(input_key: &[u8], salt: &[u8], info: &[u8], bit_length: usize) -> Vec<u8> {
    let (_, hk) = Hkdf::<Sha256>::extract(Some(salt), input_key);
    let mut om: Vec<u8> = iter::repeat(0).take(bit_length / 8).collect();
    hk.expand(info, &mut om).expect("Unable to expand!");
    return om;
}

pub fn password_key_derivation(input: &[u8], salt: &[u8], iterations: u32, bit_length: usize) -> Vec<u8> {
    let mut vec: Vec<u8> = iter::repeat(0).take(bit_length / 8).collect();
    pbkdf2::pbkdf2_hmac::<Sha256>(input, salt, iterations, &mut vec);
    return vec;
}

pub struct PBKDFParameterSet {
    iterations: u32,
    salt: [u8; 32],
}