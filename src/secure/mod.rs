use crate::crypto::constants::{CRYPTO_PUBLIC_KEY_SIZE_BYTES, CRYPTO_SYMMETRIC_KEY_LENGTH_BITS, CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES};
use crate::crypto::hash_message;
use crate::crypto::kdf::key_derivation;
use crate::crypto::spake::values::Values::SpakeVerifier;
use crate::crypto::spake::Spake2P;
use crate::network::network_message::NetworkMessage;
use crate::secure::constants::SESSION_KEYS_INFO;
use crate::secure::enums::MatterDestinationID;
use crate::secure::message::MatterMessage;
use crate::secure::protocol::communication::counters::GLOBAL_UNENCRYPTED_COUNTER;
use crate::secure::protocol::enums::{GeneralCode, ProtocolCode, ProtocolOpcode};
use crate::secure::protocol::message::ProtocolMessage;
use crate::secure::protocol::message_builder::ProtocolMessageBuilder;
use crate::secure::protocol::protocol_id::ProtocolID;
use crate::secure::session::Session;
use crate::tlv::structs::pake_1::Pake1;
use crate::tlv::structs::pake_2::Pake2;
use crate::tlv::structs::pake_3::Pake3;
use crate::tlv::structs::pbkdf_parameter_request::PBKDFParamRequest;
use crate::tlv::structs::pbkdf_parameter_response::PBKDFParamResponse;
use crate::tlv::structs::status_report::StatusReport;
use crate::tlv::tlv::TLV;
use crate::utils::{generic_error, transport_error, MatterError, MatterLayer};
use crate::{build_network_message, log_error, perform_validity_checks, process_message, ENCRYPTED_SESSIONS, START_TIME, UNENCRYPTED_SESSIONS};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use std::io::Cursor;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::thread::JoinHandle;
use GeneralCode::{Failure, Success};
use ProtocolCode::{InvalidParameter, SessionEstablishmentSuccess};
use ProtocolID::ProtocolSecureChannel;

pub mod enums;
pub mod protocol;
pub mod message;
pub mod message_header;
pub mod message_flags;
pub mod security_flags;
pub mod message_extension;
pub mod message_builder;
pub mod session;
mod constants;

/// Message processing thread
pub(crate) fn start_processing_thread(receiver: Receiver<NetworkMessage>, outgoing_sender: Sender<NetworkMessage>) -> JoinHandle<()> {
    thread::Builder::new().name("Processing thread".to_string()).stack_size(50_000 * 1024).spawn(move || {
        // let _reception_states: HashMap<u64, MessageReceptionState> = Default::default();
        // let _group_data_reception_states: HashMap<u64, MessageReceptionState> = Default::default();
        // let _group_control_reception_states: HashMap<u64, MessageReceptionState> = Default::default();

        loop {
            let message_to_process = receiver.recv();
            match message_to_process {
                Ok(network_message) => {
                    if !perform_validity_checks(&network_message.message) {
                        log_error!("Failed validity checks...");
                        continue;
                    }
                    if let Err(error) = process_message(network_message, &outgoing_sender) {
                        log_error!("Unable to process message: {:?}", error);
                    }
                }
                Err(error) => log_error!("Unable to receive the message {:?}", error)
            }
        }
    }).expect("Unable to start processing thread...")
}


pub(crate) fn process_unencrypted(matter_message: MatterMessage, protocol_message: ProtocolMessage) -> Result<NetworkMessage, MatterError> {
    let Ok(session_map) = &mut UNENCRYPTED_SESSIONS.lock() else {
        return Err(transport_error("Failed to obtain lock over UNENCRYPTED_SESSIONS"));
    };

    let Some(destination) = matter_message.header.source_node_id else {
        return Err(MatterError::new(MatterLayer::Transport, "No source node present..."));
    };
    let session_id = matter_message.header.session_id;
    let session = session_map.entry(session_id).or_insert(Default::default());
    let destination = MatterDestinationID::Node(destination);

    let tlv = TLV::try_from_cursor(&mut Cursor::new(&protocol_message.payload))?;
    let exchange_id = protocol_message.exchange_id;
    match protocol_message.opcode {
        ProtocolOpcode::PBKDFParamRequest => {
            let request = PBKDFParamRequest::try_from(tlv)?;
            let response = PBKDFParamResponse::build_for(&request)?;
            if let Some(param_set) = &response.pbkdf_parameters {
                session.salt = param_set.salt;
                session.iterations = param_set.iterations;
            }
            session.peer_session_id = request.initiator_session_id;
            session.session_id = response.session_id;

            let payload = Into::<TLV>::into(response).to_bytes();
            session.add_to_context(&protocol_message.payload);
            session.add_to_context(&payload);
            let protocol_message = ProtocolMessageBuilder::new()
                .set_opcode(ProtocolOpcode::PBKDFParamResponse)
                .set_exchange_id(exchange_id)
                .set_payload(&payload)
                .set_acknowledged_message_counter(matter_message.header.message_counter)
                .build();
            return Ok(build_network_message(protocol_message, &GLOBAL_UNENCRYPTED_COUNTER, destination));
        }
        ProtocolOpcode::PASEPake1 => {
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
            let protocol_message = ProtocolMessageBuilder::new()
                .set_acknowledged_message_counter(matter_message.header.message_counter)
                .set_payload(&payload)
                .set_opcode(ProtocolOpcode::PASEPake2)
                .set_exchange_id(exchange_id)
                .build();
            return Ok(build_network_message(protocol_message, &GLOBAL_UNENCRYPTED_COUNTER, destination));
        }
        ProtocolOpcode::PASEPake3 => {
            let pake_3 = Pake3::try_from(tlv)?;
            let Some(confirmation) = &session.confirmation else {
                return Err(transport_error("No confirmation present..."));
            };
            let is_okay = confirmation.c_a == pake_3.c_a;
            let (general_code, protocol_code) = if is_okay { (Success, SessionEstablishmentSuccess) } else { (Failure, InvalidParameter) };
            let status_report = StatusReport::new(general_code, ProtocolSecureChannel, protocol_code);
            if is_okay {
                let Ok(encrypted_sessions_map) = &mut ENCRYPTED_SESSIONS.lock() else {
                    return Err(generic_error("Unable to obtain lock over ENCRYPTED_SESSIONS"));
                };

                let kdf = key_derivation(&confirmation.k_e, None, &SESSION_KEYS_INFO, CRYPTO_SYMMETRIC_KEY_LENGTH_BITS * 3);
                let length = CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES;
                let prover_key: [u8; CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES] = kdf[..length].try_into().unwrap();
                let verifier_key: [u8; CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES] = kdf[length..2 * length].try_into().unwrap();
                let attestation_challenge: [u8; CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES] = kdf[2 * length..].try_into().unwrap();
                let session_id = session.session_id;
                let session = Session {
                    peer_session_id: session.peer_session_id,
                    session_id,
                    prover_key,
                    verifier_key,
                    attestation_challenge,
                    timestamp: START_TIME.elapsed()?.as_secs(),
                };
                session_map.remove_entry(&session_id);
                encrypted_sessions_map.insert(session_id, session);
            }
            let protocol_message = ProtocolMessageBuilder::new()
                .set_exchange_id(exchange_id)
                .set_acknowledged_message_counter(matter_message.header.message_counter)
                .set_opcode(ProtocolOpcode::StatusReport)
                .set_payload(&status_report.to_bytes())
                .build();
            return Ok(build_network_message(protocol_message, &GLOBAL_UNENCRYPTED_COUNTER, destination));
        }
        _ => {
            todo!("Received OPCODE: {:?}", protocol_message.opcode);
        }
    }
    Err(MatterError::new(MatterLayer::Generic, "Unable to process unencrypted session..."))
}