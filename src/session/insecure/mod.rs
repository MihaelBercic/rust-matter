pub(crate) mod session;


use crate::constants::UNSPECIFIED_NODE_ID;
use crate::crypto::constants::{CRYPTO_PUBLIC_KEY_SIZE_BYTES, CRYPTO_SESSION_KEYS_INFO, CRYPTO_SYMMETRIC_KEY_LENGTH_BITS, CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES};
use crate::crypto::hash_message;
use crate::crypto::kdf::key_derivation;
use crate::crypto::spake::values::Values::SpakeVerifier;
use crate::crypto::spake::Spake2P;
use crate::logging::{color_blue, color_red, color_reset};
use crate::network::network_message::NetworkMessage;
use crate::session::counters::{increase_counter, GLOBAL_UNENCRYPTED_COUNTER};
use crate::session::matter::builder::MatterMessageBuilder;
use crate::session::matter::enums::SessionOrigin::Pase;
use crate::session::matter::enums::{MatterDestinationID, MessageType};
use crate::session::matter_message::MatterMessage;
use crate::session::message_reception::MessageReceptionState;
use crate::session::protocol::enums::SecureChannelGeneralCode::{Failure, Success};
use crate::session::protocol::enums::SecureChannelProtocolOpcode;
use crate::session::protocol::enums::SecureStatusProtocolCode::{InvalidParameter, SessionEstablishmentSuccess};
use crate::session::protocol::message_builder::ProtocolMessageBuilder;
use crate::session::protocol::protocol_id::ProtocolID;
use crate::session::protocol_message::ProtocolMessage;
use crate::session::secure::session::Session;
use crate::session::SessionRole;
use crate::tlv::structs::pake_1::Pake1;
use crate::tlv::structs::pake_2::Pake2;
use crate::tlv::structs::pake_3::Pake3;
use crate::tlv::structs::pbkdf_parameter_request::PBKDFParamRequest;
use crate::tlv::structs::pbkdf_parameter_response::PBKDFParamResponse;
use crate::tlv::structs::status_report;
use crate::tlv::structs::status_report::StatusReport;
use crate::tlv::tlv::TLV;
use crate::utils::{generic_error, transport_error, MatterError};
use crate::{log_info, ENCRYPTED_SESSIONS, START_TIME, UNENCRYPTED_SESSIONS};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use std::io::Cursor;

///
/// @author Mihael Berčič
/// @date 18. 9. 24
///

pub(crate) fn process_insecure(matter_message: MatterMessage) -> Result<NetworkMessage, MatterError> {
    let protocol_message = ProtocolMessage::try_from(&matter_message.payload[..])?;
    let source_node_id = matter_message.header.source_node_id.unwrap_or(UNSPECIFIED_NODE_ID);

    let mut builder = match protocol_message.protocol_id {
        ProtocolID::ProtocolSecureChannel => process_secure_channel(&matter_message, protocol_message, source_node_id),
        ProtocolID::ProtocolInteractionModel => todo!("Not yet implemented"),
        ProtocolID::ProtocolBdx => todo!("Not yet implemented"),
        ProtocolID::ProtocolUserDirectedCommissioning => todo!("Not yet implemented"),
        ProtocolID::ProtocolForTesting => todo!("Not yet implemented"),
    }?;

    let payload: Vec<u8> = builder.build().into();
    let message = MatterMessageBuilder::new()
        .set_counter(increase_counter(&GLOBAL_UNENCRYPTED_COUNTER))
        .set_destination(MatterDestinationID::Node(source_node_id))
        .set_payload(&payload)
        .build();
    Ok(NetworkMessage {
        address: None,
        message,
        retry_counter: 0,
    })
}

fn process_secure_channel(message: &MatterMessage, protocol_message: ProtocolMessage, peer_node_id: u64) -> Result<ProtocolMessageBuilder, MatterError> {
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

    let Ok(session_map) = &mut UNENCRYPTED_SESSIONS.lock() else {
        return Err(transport_error("Failed to obtain lock over UNENCRYPTED_SESSIONS"));
    };
    let session_id = 0;
    let session = session_map.entry(session_id).or_insert(Default::default());
    let tlv = TLV::try_from_cursor(&mut Cursor::new(&protocol_message.payload))?;
    let exchange_id = protocol_message.exchange_id;
    match opcode {
        SecureChannelProtocolOpcode::PBKDFParamRequest => {
            let request = PBKDFParamRequest::try_from(tlv)?;
            let response = PBKDFParamResponse::build_for(&request)?;
            if let Some(param_set) = &response.pbkdf_parameters {
                session.salt = param_set.salt;
                session.iterations = param_set.iterations;
            }
            session.peer_session_id = request.initiator_session_id;
            session.session_id = response.session_id;

            let payload = TLV::from(response).to_bytes();
            session.add_to_context(&protocol_message.payload);
            session.add_to_context(&payload);
            let builder = ProtocolMessageBuilder::new()
                .set_acknowledged_message_counter(message.header.message_counter)
                .set_opcode(SecureChannelProtocolOpcode::PBKDFParamResponse as u8)
                .set_exchange_id(exchange_id)
                .set_payload(&payload);
            Ok(builder)
        }
        SecureChannelProtocolOpcode::PASEPake1 => {
            let salt = &session.salt;
            let iterations = session.iterations;
            let pake_1 = Pake1::try_from(tlv)?;
            let s2p = Spake2P::new();
            let prover = Spake2P::compute_prover(20202021, salt, iterations);
            let verifier = Spake2P::compute_verifier(20202021, salt, iterations);
            let p_b: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES] = s2p.compute_public_verifier(&verifier.w0)?.to_encoded_point(false).as_bytes().try_into().unwrap();
            let context = hash_message(&session.context);
            let mut transcript = s2p.compute_transcript(&context, &[], &[], SpakeVerifier(verifier), &pake_1.p_a, &p_b);
            let confirmation = s2p.compute_confirmation_values(&transcript, &pake_1.p_a, &p_b, 256);
            let pake_2 = Pake2 { p_b, c_b: confirmation.cB };
            let pake_tlv: TLV = pake_2.into();
            let payload = pake_tlv.to_bytes();
            session.p_a = Some(pake_1.p_a);
            session.p_b = Some(p_b);
            session.confirmation = Some(confirmation);
            let builder = ProtocolMessageBuilder::new()
                .set_acknowledged_message_counter(message.header.message_counter)
                .set_payload(&payload)
                .set_opcode(SecureChannelProtocolOpcode::PASEPake2 as u8)
                .set_exchange_id(exchange_id);
            Ok(builder)
        }
        SecureChannelProtocolOpcode::PASEPake3 => {
            let pake_3 = Pake3::try_from(tlv)?;
            let Some(confirmation) = &session.confirmation else {
                return Err(transport_error("No confirmation present..."));
            };
            let is_okay = confirmation.c_a == pake_3.c_a;
            let (general_code, protocol_code) = if is_okay { (Success, SessionEstablishmentSuccess) } else { (Failure, InvalidParameter) };
            let status_report = StatusReport::new(general_code, ProtocolID::ProtocolSecureChannel, protocol_code);
            if is_okay {
                let Ok(encrypted_sessions_map) = &mut ENCRYPTED_SESSIONS.lock() else {
                    return Err(generic_error("Unable to obtain lock over ENCRYPTED_SESSIONS"));
                };

                let kdf = key_derivation(&confirmation.k_e, None, &CRYPTO_SESSION_KEYS_INFO, CRYPTO_SYMMETRIC_KEY_LENGTH_BITS * 3);
                let length = CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES;
                let prover_key: [u8; CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES] = kdf[..length].try_into().unwrap();
                let verifier_key: [u8; CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES] = kdf[length..2 * length].try_into().unwrap();
                let attestation_challenge: [u8; CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES] = kdf[2 * length..].try_into().unwrap();
                let session_id = session.session_id;
                let session = Session {
                    session_origin: Pase,
                    session_role: SessionRole::Verifier,
                    peer_session_id: session.peer_session_id,
                    session_id,
                    prover_key,
                    verifier_key,
                    attestation_challenge,
                    timestamp: START_TIME.elapsed()?.as_secs(),
                    message_counter: 0, // TODO: maybe change?
                    message_reception_state: MessageReceptionState {
                        peer_node_id,
                        message_type: MessageType::Command,
                        max_counter: 0,
                        bitmap: 0,
                    },
                    fabric_index: 0,
                    peer_node_id: MatterDestinationID::Node(peer_node_id),
                    resumption_id: 0,
                    active_timestamp: 0,
                    session_idle_interval: 500,
                    session_active_interval: 600,
                    session_active_threshold: 4000,
                    peer_active_mode: false,
                };
                session_map.remove_entry(&session_id);
                encrypted_sessions_map.insert(session_id, session);
            }
            let builder = ProtocolMessageBuilder::new()
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
