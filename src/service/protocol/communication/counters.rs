use std::sync::Mutex;

use crate::crypto::random_bits;

pub const GLOBAL_UNENCRYPTED_COUNTER: Mutex<u32> = Mutex::new(0u32);

/// Initialises the counter with the CRYPTO_DRBG(len = 28) + 1;
pub fn initialize_counter(counter: &mut Mutex<u32>) {
    let bits = random_bits(28);
    let mut array = [0u8; 4];
    array.copy_from_slice(&bits);
    let number_be = u32::from_be_bytes(array) + 1;
    *counter.lock().unwrap() = number_be;

    println!("Counter initialised to {}", number_be);
}