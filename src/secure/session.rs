use crate::crypto::constants::{CONTEXT_PREFIX_VALUE, CRYPTO_PBKDF_ITERATIONS_MIN, CRYPTO_PUBLIC_KEY_SIZE_BYTES};
use crate::crypto::spake::spake_confirmation::S2PConfirmation;
use crate::crypto::spake::values_initiator::ProverValues;
use crate::crypto::spake::values_responder::VerifierValues;
use crate::tlv::structs::pake_1::Pake1;
use crate::tlv::structs::pbkdf_parameter_request::PBKDFParamRequest;
use crate::tlv::structs::pbkdf_parameter_response::PBKDFParamResponse;

///
/// @author Mihael Berčič
/// @date 17. 8. 24
///
pub struct UnencryptedSession {
    pub session_id: u16,
    pub initiator_session_id: u16,
    pub iterations: u32,
    pub salt: [u8; 32],
    pub p_a: Option<[u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES]>,
    pub p_b: Option<[u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES]>,
    pub confirmation: Option<S2PConfirmation>,
    pub context: Vec<u8>,
    pub timestamp: u64,
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
            initiator_session_id: 0,
            context: CONTEXT_PREFIX_VALUE.to_vec(),
            confirmation: None,
            timestamp: 0,
        }
    }
}

#[derive(Clone)]
pub struct Session;

#[derive(Clone)]
pub struct Exchange {
    pub id: u16,
    pub pbkdf_request: Option<PBKDFParamRequest>,
    pub pbkdf_response: Option<PBKDFParamResponse>,
    pub request_bytes: Vec<u8>,
    pub response_bytes: Vec<u8>,
    pub pake1: Option<Pake1>,
    pub values_initiator: Option<ProverValues>,
    pub values_responder: Option<VerifierValues>,
    pub session: Option<Session>,
}

impl Exchange {
    pub fn new(id: u16) -> Exchange {
        Self {
            id,
            pbkdf_request: None,
            pbkdf_response: None,
            request_bytes: vec![],
            response_bytes: vec![],
            pake1: None,
            values_initiator: None,
            values_responder: None,
            session: None,
        }
    }
}

