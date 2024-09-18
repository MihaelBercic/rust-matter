use crate::crypto::constants::{CONTEXT_PREFIX_VALUE, CRYPTO_PBKDF_ITERATIONS_MIN, CRYPTO_PUBLIC_KEY_SIZE_BYTES, CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES};
use crate::crypto::spake::spake_confirmation::SpakeConfirmation;

///
/// @author Mihael Berčič
/// @date 17. 8. 24
///
#[derive(Debug)]
pub struct UnencryptedSession {
    pub peer_session_id: u16,
    pub session_id: u16,
    pub iterations: u32,
    pub salt: [u8; 32],
    pub p_a: Option<[u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES]>,
    pub p_b: Option<[u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES]>,
    pub confirmation: Option<SpakeConfirmation>,
    pub context: Vec<u8>,
}

impl UnencryptedSession {
    pub fn add_to_context(&mut self, data: &[u8]) {
        self.context.extend_from_slice(data);
    }
}

impl Default for UnencryptedSession {
    fn default() -> Self {
        Self {
            session_id: 0,
            salt: Default::default(),
            p_a: None,
            p_b: None,
            iterations: CRYPTO_PBKDF_ITERATIONS_MIN,
            peer_session_id: 0,
            context: CONTEXT_PREFIX_VALUE.to_vec(),
            confirmation: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Session {
    pub session_id: u16,
    pub peer_session_id: u16,
    pub prover_key: [u8; CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES],
    pub verifier_key: [u8; CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES],
    pub attestation_challenge: [u8; CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES],
    pub timestamp: u64,
}