pub(crate) mod session;


use crate::crypto::constants::{CRYPTO_PUBLIC_KEY_SIZE_BYTES, CRYPTO_SESSION_KEYS_INFO, CRYPTO_SYMMETRIC_KEY_LENGTH_BITS, CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES};
use crate::crypto::hash_message;
use crate::crypto::kdf::key_derivation;
use crate::crypto::spake::values::Values::SpakeVerifier;
use crate::crypto::spake::Spake2P;
use crate::log_info;
use crate::logging::{color_blue, color_red, color_reset};
use crate::session::matter::enums::MatterDestinationID;
use crate::session::matter::enums::SessionOrigin::Pase;
use crate::session::matter_message::MatterMessage;
use crate::session::protocol::enums::SecureChannelGeneralCode::{Failure, Success};
use crate::session::protocol::enums::SecureChannelProtocolOpcode;
use crate::session::protocol::enums::SecureStatusProtocolCode::{InvalidParameter, SessionEstablishmentSuccess};
use crate::session::protocol::message_builder::ProtocolMessageBuilder;
use crate::session::protocol::protocol_id::ProtocolID;
use crate::session::protocol::protocol_id::ProtocolID::ProtocolSecureChannel;
use crate::session::protocol_message::ProtocolMessage;
use crate::session::secure::session::Session;
use crate::tlv::structs::pake_1::Pake1;
use crate::tlv::structs::pake_2::Pake2;
use crate::tlv::structs::pake_3::Pake3;
use crate::tlv::structs::pbkdf_parameter_request::PBKDFParamRequest;
use crate::tlv::structs::pbkdf_parameter_response::PBKDFParamResponse;
use crate::tlv::structs::status_report;
use crate::tlv::structs::status_report::StatusReport;
use crate::tlv::tlv::TLV;
use crate::utils::{generic_error, transport_error, MatterError};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use std::io::Cursor;

///
/// @author Mihael Berčič
/// @date 18. 9. 24
///

pub(crate) fn process_secure_channel(message: &MatterMessage, protocol_message: ProtocolMessage, peer_node_id: u64, session: &mut Session) -> Result<ProtocolMessageBuilder, MatterError> {
    let opcode = SecureChannelProtocolOpcode::from(protocol_message.opcode);
    log_info!("{color_red}|{:?}|{color_blue}{:?}|{color_reset}", &protocol_message.protocol_id, opcode);

    match opcode {
        SecureChannelProtocolOpcode::StatusReport => {
            let status_report = status_report::StatusReport::try_from(protocol_message);
            let representation = format!("{:?}", status_report);
            return Err(transport_error(&representation));
        }
        SecureChannelProtocolOpcode::MRPStandaloneAcknowledgement => {
            // TODO: Remove from retransmission...
            return Err(generic_error("Nothing to do about this..."))
        }
        _ => ()
    }

    let Some(session_setup) = &mut session.session_setup else {
        return Err(transport_error("Missing session in the map!"))
    };
    let tlv = TLV::try_from_cursor(&mut Cursor::new(&protocol_message.payload))?;
    let exchange_id = protocol_message.exchange_id;
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

            let payload = TLV::from(response).to_bytes();
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
            let p_b: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES] = s2p.compute_public_verifier(&verifier.w0)?.to_encoded_point(false).as_bytes().try_into().unwrap();
            let context = hash_message(&session_setup.context);
            let mut transcript = s2p.compute_transcript(&context, &[], &[], SpakeVerifier(verifier), &pake_1.p_a, &p_b);
            let confirmation = s2p.compute_confirmation_values(&transcript, &pake_1.p_a, &p_b, 256);
            let pake_2 = Pake2 { p_b, c_b: confirmation.cB };
            let pake_tlv: TLV = pake_2.into();
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
            let (general_code, protocol_code) = if is_okay { (Success, SessionEstablishmentSuccess) } else { (Failure, InvalidParameter) };
            let status_report = StatusReport::new(general_code, ProtocolID::ProtocolSecureChannel, protocol_code);
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
                dbg!(session);
            }
            let builder = ProtocolMessageBuilder::new()
                .set_protocol(ProtocolSecureChannel)
                .set_acknowledged_message_counter(message.header.message_counter)
                .set_exchange_id(exchange_id)
                .set_opcode(SecureChannelProtocolOpcode::StatusReport as u8)
                .set_payload(&status_report.to_bytes());
            Ok(builder)
        }
        _ => {
            todo!("Received OPCODE: {:?}", protocol_message.opcode);
        }
    }
}
