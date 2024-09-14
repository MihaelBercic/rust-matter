use crate::crypto::spake::values_initiator::ProverValues;
use crate::crypto::spake::values_responder::VerifierValues;
use crate::tlv::structs::pake_1::Pake1;
use crate::tlv::structs::pbkdf_parameter_request::PBKDFParamRequest;
use crate::tlv::structs::pbkdf_parameter_response::PBKDFParamResponse;

///
/// @author Mihael Berčič
/// @date 17. 8. 24
///

#[derive(Clone)]
pub struct Session {}


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
