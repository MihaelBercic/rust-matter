use crate::crypto::spake::values_initiator::ValuesInitiator;
use crate::crypto::spake::values_responder::ValuesResponder;
use crate::tlv::structs::pake_1::Pake1;
use crate::tlv::structs::pbkdf_param_request::PBKDFParamRequest;
use crate::tlv::structs::pbkdf_param_response::PBKDFParamResponse;

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
    pub pake1: Option<Pake1>,
    pub values_initiator: Option<ValuesInitiator>,
    pub values_responder: Option<ValuesResponder>,
    pub session: Option<Session>,
}

impl Exchange {
    pub fn new(id: u16) -> Exchange {
        Self {
            id,
            pbkdf_request: None,
            pbkdf_response: None,
            pake1: None,
            values_initiator: None,
            values_responder: None,
            session: None,
        }
    }
}
