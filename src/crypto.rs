use hmac::{Hmac, Mac};
use hmac::digest::MacError;
use sha2::{Digest, Sha256};

pub fn hash_message(message: &[u8]) -> [u8; 32] {
    /*
    int CRYPTO_HASH_LEN_BITS := 256
    int CRYPTO_HASH_LEN_BYTES := 32
    int CRYPTO_HASH_BLOCK_LEN_BYTES := 64
     */
    let mut hasher = Sha256::new();
    hasher.update(message);
    let result = hasher.finalize();
    let mut output_data: [u8; 32] = [0; 32];
    output_data.copy_from_slice(&result[..]);
    return output_data;
}

type HmacSha256 = Hmac<Sha256>;

pub fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC should take any key size");
    mac.update(message);
    let result = mac.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result.into_bytes()[..]);
    return output;
}

pub fn verify_hmac(key: &[u8], message: &[u8], code_bytes: &[u8]) -> Result<(), MacError> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(message);
    return mac.verify_slice(&code_bytes[..]);
}
