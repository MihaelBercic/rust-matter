use byteorder::{LittleEndian, WriteBytesExt};
use rand::{thread_rng, Rng};

use crate::crypto::constants::{CRYPTO_PBKDF_ITERATIONS_MAX, CRYPTO_PBKDF_ITERATIONS_MIN};
use crate::crypto::{random_bits, random_bytes};
use crate::tlv::element_type::ElementType::Structure;
use crate::tlv::structs::pbkdf_parameter_request::{PBKDFParamRequest, SessionParameter};
use crate::tlv::structs::pbkdf_parameter_set::PBKDFParameterSet;
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::Tlv;
use crate::utils::MatterError;

///
/// @author Mihael Berčič
/// @date 6. 8. 24
///
#[derive(Debug, Clone)]
pub struct PBKDFParamResponse {
    pub initiator_random: Vec<u8>, // octet string 32
    pub responder_random: Vec<u8>, // octet string 32
    pub session_id: u16,
    pub pbkdf_parameters: Option<PBKDFParameterSet>,
    pub responder_session_params: Option<SessionParameter>,
}

impl PBKDFParamResponse {
    /// Core spec: page 159
    pub fn build_for(request: &PBKDFParamRequest) -> Result<Self, MatterError> {
        // verify passcode is 0
        let responder_random = random_bits(32 * 8);
        let session_id = u16::from_le_bytes(random_bytes::<2>()); // set local session identifier
        let peer_session_id = request.initiator_session_id;
        let mut pbkdf_parameters = match request.has_params {
            true => None,
            _ => {
                let mut random = thread_rng();
                let salt = random_bytes::<32>();
                let iterations = random.gen_range(CRYPTO_PBKDF_ITERATIONS_MIN..=CRYPTO_PBKDF_ITERATIONS_MAX);

                let mut salt = [
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                ];
                let iterations = 1000;
                Some(PBKDFParameterSet { iterations, salt })
            }
        };
        let responder_session_params: Option<SessionParameter> = request.initiator_session_parameters.clone();
        Ok(Self {
            initiator_random: request.initiator_random.clone(),
            responder_random,
            session_id,
            pbkdf_parameters,
            responder_session_params,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut vec = vec![];
        vec.extend_from_slice(&self.initiator_random);
        vec.extend_from_slice(&self.responder_random);
        vec.write_u16::<LittleEndian>(self.session_id);
        if let Some(session) = &self.responder_session_params {
            vec.extend_from_slice(&session.as_bytes())
        }
        vec
    }
}

impl From<PBKDFParamResponse> for Tlv {
    fn from(value: PBKDFParamResponse) -> Self {
        let mut children = vec![
            Tlv::new(value.initiator_random.into(), ContextSpecific8, Tag::short(1)),
            Tlv::new(value.responder_random.into(), ContextSpecific8, Tag::short(2)),
            Tlv::new(value.session_id.into(), ContextSpecific8, Tag::short(3)),
        ];
        if let Some(parameters) = value.pbkdf_parameters {
            let mut tlv: Tlv = parameters.into();
            tlv.control.tag_control = ContextSpecific8;
            tlv.tag.tag_number = Some(Short(4));
            children.push(tlv);
        }
        if let Some(parameters) = value.responder_session_params {
            let mut tlv: Tlv = parameters.into();
            tlv.control.tag_control = ContextSpecific8;
            tlv.tag.tag_number = Some(Short(5));
            children.push(tlv);
        }
        Tlv::simple(Structure(children))
    }
}
