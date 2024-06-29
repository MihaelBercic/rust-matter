use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering::Relaxed;

use crate::crypto::random_bits;

pub const GLOBAL_UNENCRYPTED_COUNTER: AtomicU32 = AtomicU32::new(0);
pub const GLOBAL_GROUP_ENCRYPTED_DATA_MESSAGE_COUNTER: AtomicU32 = AtomicU32::new(0); // TODO: MUST BE IN PERMANENT STORAGE
pub const GLOBAL_GROUP_ENCRYPTED_CONTROL_MESSAGE_COUNTER: AtomicU32 = AtomicU32::new(0); // TODO: MUST BE IN PERMANENT STORAGE

/// Initialises the counter with the CRYPTO_DRBG(len = 28) + 1;
pub fn initialize_counter(counter: &AtomicU32) {
    let bits = random_bits(28);
    let mut array = [0u8; 4];
    array.copy_from_slice(&bits);
    let number_be = u32::from_be_bytes(array) + 1;
    counter.store(number_be, Relaxed);
    println!("Counter initialised to {}", number_be);
}

/// Increases the counter by one (1).
pub fn increase_counter(counter: &AtomicU32) {
    counter.fetch_add(1, Relaxed);
}