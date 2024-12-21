use crate::crypto::{
    constants::{CONTEXT_PREFIX_VALUE, CRYPTO_PBKDF_ITERATIONS_MIN, CRYPTO_PUBLIC_KEY_SIZE_BYTES},
    spake::spake_confirmation::SpakeConfirmation,
};

#[derive(Debug, Clone)]
pub struct SessionSetup {
    pub peer_session_id: u16,
    pub session_id: u16,
    pub iterations: u32,
    pub salt: [u8; 32],
    pub p_a: Option<[u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES]>,
    pub p_b: Option<[u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES]>,
    pub confirmation: Option<SpakeConfirmation>,
    pub context: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CaseSessionSetup {
    pub context: Vec<u8>,
    pub ipk: Vec<u8>,
}

impl SessionSetup {
    pub fn add_to_context(&mut self, data: &[u8]) {
        self.context.extend_from_slice(data);
    }
}

impl Default for SessionSetup {
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
