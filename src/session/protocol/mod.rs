use crate::crypto::constants::{
    CRYPTO_AEAD_MIC_LENGTH_BYTES, CRYPTO_HASH_LEN_BYTES, CRYPTO_PUBLIC_KEY_SIZE_BYTES, CRYPTO_SESSION_KEYS_INFO, CRYPTO_SYMMETRIC_KEY_LENGTH_BITS,
    CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES,
};
use crate::crypto::kdf::key_derivation;
use crate::crypto::spake::values::Values::SpakeVerifier;
use crate::crypto::spake::Spake2P;
use crate::crypto::{self, hash_message, kdf};
use crate::mdns::device_information::Details;
use crate::session::matter::enums::MatterDestinationID;
use crate::session::matter::enums::SessionOrigin::Pase;
use crate::session::matter_message::MatterMessage;
use crate::session::protocol::enums::SecureChannelGeneralCode::{Failure, Success};
use crate::session::protocol::enums::SecureChannelProtocolOpcode;
use crate::session::protocol::enums::SecureStatusProtocolCode::{InvalidParameter, SessionEstablishmentSuccess};
use crate::session::protocol::message_builder::ProtocolMessageBuilder;
use crate::session::protocol::protocol_id::ProtocolID::ProtocolSecureChannel;
use crate::session::protocol_message::ProtocolMessage;
use crate::session::session::Session;
use crate::tlv::structs::PBKDFParamResponse;
use crate::tlv::structs::Pake1;
use crate::tlv::structs::Pake2;
use crate::tlv::structs::Pake3;
use crate::tlv::structs::StatusReport;
use crate::tlv::structs::{PBKDFParamRequest, SessionParameter};
use crate::tlv::tlv::Tlv;
use crate::utils::{bail_tlv, generic_error, transport_error, MatterError};
use crate::{log_debug, log_info, tlv};
use byteorder::{WriteBytesExt, LE};
use interaction::cluster::operational_credentials::MatterCertificate;
use libc::LOG_INFO;
use p256::ecdh::EphemeralSecret;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use std::io::Cursor;

use super::Device;

pub mod enums;
pub mod exchange_flags;
pub mod interaction;
pub mod message_builder;
pub mod protocol_id;
pub mod secured_extensions;

pub(crate) fn process_secure_channel(
    message: &MatterMessage,
    protocol_message: ProtocolMessage,
    peer_node_id: u64,
    session: &mut Session,
    device: &mut Device,
) -> Result<ProtocolMessageBuilder, MatterError> {
    let opcode = SecureChannelProtocolOpcode::from(protocol_message.opcode);
    match opcode {
        SecureChannelProtocolOpcode::StatusReport => {
            let status_report = StatusReport::try_from(protocol_message);
            let representation = format!("{:?}", status_report);
            return Err(transport_error(&representation));
        }
        SecureChannelProtocolOpcode::MRPStandaloneAcknowledgement => {
            // TODO: Remove from retransmission...
            return Err(generic_error("Nothing to do about this..."));
        }
        _ => (),
    }

    let Some(session_setup) = &mut session.session_setup else {
        return Err(transport_error("Missing session in the map!"));
    };
    let tlv = Tlv::try_from_cursor(&mut Cursor::new(&protocol_message.payload))?;
    let exchange_id = protocol_message.exchange_id;
    let details = &mut device.details;
    match opcode {
        SecureChannelProtocolOpcode::PBKDFParamRequest => {
            let request = PBKDFParamRequest::try_from(tlv)?;
            let response = PBKDFParamResponse::build_for(&request)?;
            if let Some(param_set) = &response.pbkdf_parameters {
                session_setup.salt = param_set.salt;
                session_setup.iterations = param_set.iterations;
            }
            session_setup.peer_session_id = request.initiator_session_id;
            session_setup.session_id = response.session_id;

            let payload = Tlv::from(response).to_bytes();
            session_setup.add_to_context(&protocol_message.payload);
            session_setup.add_to_context(&payload);
            let builder = ProtocolMessageBuilder::new()
                .set_protocol(ProtocolSecureChannel)
                .set_acknowledged_message_counter(message.header.message_counter)
                .set_opcode(SecureChannelProtocolOpcode::PBKDFParamResponse as u8)
                .set_exchange_id(exchange_id)
                .set_payload(&payload);
            Ok(builder)
        }
        SecureChannelProtocolOpcode::PASEPake1 => {
            let salt = &session_setup.salt;
            let iterations = session_setup.iterations;
            let pake_1 = Pake1::try_from(tlv)?;
            let s2p = Spake2P::new();
            let prover = Spake2P::compute_prover(20202021, salt, iterations);
            let verifier = Spake2P::compute_verifier(20202021, salt, iterations);
            let p_b: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES] = s2p
                .compute_public_verifier(&verifier.w0)?
                .to_encoded_point(false)
                .as_bytes()
                .try_into()
                .unwrap();
            let context = hash_message(&session_setup.context);
            let mut transcript = s2p.compute_transcript(&context, &[], &[], SpakeVerifier(verifier), &pake_1.p_a, &p_b);
            let confirmation = s2p.compute_confirmation_values(&transcript, &pake_1.p_a, &p_b, 256);
            let pake_2 = Pake2 { p_b, c_b: confirmation.cB };
            let pake_tlv: Tlv = pake_2.into();
            let payload = pake_tlv.to_bytes();
            session_setup.p_a = Some(pake_1.p_a);
            session_setup.p_b = Some(p_b);
            session_setup.confirmation = Some(confirmation);
            let builder = ProtocolMessageBuilder::new()
                .set_protocol(ProtocolSecureChannel)
                .set_acknowledged_message_counter(message.header.message_counter)
                .set_payload(&payload)
                .set_opcode(SecureChannelProtocolOpcode::PASEPake2 as u8)
                .set_exchange_id(exchange_id);
            Ok(builder)
        }
        SecureChannelProtocolOpcode::PASEPake3 => {
            let pake_3 = Pake3::try_from(tlv)?;
            let Some(confirmation) = &session_setup.confirmation else {
                return Err(transport_error("No confirmation present..."));
            };
            let is_okay = confirmation.c_a == pake_3.c_a;
            let (general_code, protocol_code) = if is_okay {
                (Success, SessionEstablishmentSuccess)
            } else {
                (Failure, InvalidParameter)
            };
            let status_report = StatusReport::new(general_code, ProtocolSecureChannel, protocol_code);
            if is_okay {
                let kdf = key_derivation(&confirmation.k_e, None, &CRYPTO_SESSION_KEYS_INFO, CRYPTO_SYMMETRIC_KEY_LENGTH_BITS * 3);
                let length = CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES;
                let prover_key: [u8; CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES] = kdf[..length].try_into().unwrap();
                let verifier_key: [u8; CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES] = kdf[length..2 * length].try_into().unwrap();
                let attestation_challenge: [u8; CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES] = kdf[2 * length..].try_into().unwrap();
                let session_id = session_setup.session_id;
                session.session_origin = Pase;
                session.peer_session_id = session_setup.peer_session_id;
                session.session_id = session_id;
                session.prover_key = prover_key;
                session.verifier_key = verifier_key;
                session.attestation_challenge = attestation_challenge;
                session.timestamp = crate::START_TIME.elapsed()?.as_secs();
                session.peer_node_id = MatterDestinationID::Node(peer_node_id);
                session.session_setup = None;
            }
            let builder = ProtocolMessageBuilder::new()
                .set_protocol(ProtocolSecureChannel)
                .set_acknowledged_message_counter(message.header.message_counter)
                .set_exchange_id(exchange_id)
                .set_opcode(SecureChannelProtocolOpcode::StatusReport as u8)
                .set_payload(&status_report.to_bytes());
            Ok(builder)
        }
        SecureChannelProtocolOpcode::CASESigma1 => {
            let sigma = Sigma1::try_from(tlv).unwrap();
            let mut matching_index: u64 = 0u64;
            log_info!("We have sigma: {:?}", sigma);
            for (index, noc) in details.nocs.clone().iter().enumerate() {
                let fabric = details.fabrics.get(index).unwrap();
                let cert = details.trusted_root_certificates.get(index).unwrap();
                let cert = MatterCertificate::try_from(&cert[..]).unwrap();
                let root_public_key = cert.ec_public_key;
                let key_set = details.group_keys.get(index).unwrap();
                let compressed_fabric = details.compressed_fabric_ids.get(index).unwrap();
                let ipk = key_derivation(
                    &key_set.epoch_key,
                    Some(&compressed_fabric[..]),
                    b"GroupKey v1.0",
                    CRYPTO_SYMMETRIC_KEY_LENGTH_BITS,
                );
                let candidate_destination_id =
                    compute_destination_id(&root_public_key, fabric.fabric_id, fabric.node_id, &sigma.initiator_random, &ipk);

                if candidate_destination_id == sigma.destination_id {
                    log_debug!("Found our destination Candidate ID! {}", hex::encode(candidate_destination_id));
                    matching_index = index as u64;
                    break;
                }
            }
            let fabric = details.fabrics.get(matching_index as usize).unwrap();
            session.peer_session_id = sigma.initiator_session_id;
            session.fabric_index = matching_index;
            session.resumption_id = 6969; // TODO: make random?
            session.local_node_id = fabric.node_id;

            if let Some(params) = sigma.initiator_session_params {
                if let Some(idle) = params.session_idle_interval {
                    // TODO: idk why.
                }
            }

            let ephemeral_key_pair = crypto::generate_ephemeral_pair();
            let eph_public_key = ephemeral_key_pair.public_key();
            // https://github.com/adafruit/CircuitMatter/blob/main/circuitmatter/session.py#L611C5-L613C10
            let shared_secret = crypto::ecdh(ephemeral_key_pair, &sigma.initiator_eph_public_key);
            todo!("Finish CASE Sigma 1 implementation.")
        }
        _ => todo!("Received OPCODE: {:?}", protocol_message.opcode),
    }
}

fn compute_destination_id(root_public_key: &[u8], fabric_id: u64, node_id: u64, initiator_random: &[u8], ipk: &[u8]) -> [u8; 32] {
    let mut message = vec![];
    message.extend_from_slice(initiator_random);
    message.extend_from_slice(root_public_key);
    message.write_u64::<LE>(fabric_id);
    message.write_u64::<LE>(node_id);
    crypto::hmac(ipk, &message)
}

#[derive(Debug)]
struct Sigma1 {
    pub initiator_random: Vec<u8>,
    pub initiator_session_id: u16,
    pub destination_id: [u8; CRYPTO_HASH_LEN_BYTES],
    pub initiator_eph_public_key: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
    pub initiator_session_params: Option<SessionParameter>,
    pub resumption_id: Option<Vec<u8>>,
    pub initiator_resume_mic: Option<[u8; CRYPTO_AEAD_MIC_LENGTH_BYTES]>,
}

impl TryFrom<Tlv> for Sigma1 {
    type Error = MatterError;

    fn try_from(value: Tlv) -> Result<Self, Self::Error> {
        let mut sigma = Self {
            initiator_random: vec![],
            initiator_session_id: 0,
            destination_id: [0; CRYPTO_HASH_LEN_BYTES],
            initiator_eph_public_key: [0; CRYPTO_PUBLIC_KEY_SIZE_BYTES],
            initiator_session_params: None,
            resumption_id: None,
            initiator_resume_mic: None,
        };

        let tlv::element_type::ElementType::Structure(children) = value.control.element_type else {
            bail_tlv!("Incorrect Tlv structure.")
        };

        for child in children {
            let Some(tlv::tag_number::TagNumber::Short(tag)) = child.tag.tag_number else {
                bail_tlv!("Incorrect tag encoding.")
            };
            let element_type = child.control.element_type;
            let message: &str = &format!("The tag {} is not expected", tag);
            match tag {
                1 => sigma.initiator_random = element_type.into_octet_string()?,
                2 => sigma.initiator_session_id = element_type.into_u16()?,
                3 => sigma.destination_id = element_type.into_octet_string()?.try_into()?,
                4 => sigma.initiator_eph_public_key = element_type.into_octet_string()?.try_into()?,
                5 => sigma.initiator_session_params = Some(SessionParameter::try_from(Tlv::simple(element_type))?),
                6 => sigma.resumption_id = Some(element_type.into_octet_string()?),
                7 => sigma.initiator_resume_mic = Some(element_type.into_octet_string()?.try_into()?),
                _ => bail_tlv!(message),
            }
        }
        Ok(sigma)
    }
}
