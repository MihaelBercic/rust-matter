use crate::crypto::constants::CRYPTO_PUBLIC_KEY_SIZE_BYTES;
use crate::crypto::hash_message;
use crate::crypto::spake::values::Values::SpakeVerifier;
use crate::crypto::spake::Spake2P;
use crate::network::network_message::NetworkMessage;
use crate::secure::message::MatterMessage;
use crate::secure::protocol::enums::ProtocolCode::InvalidParameter;
use crate::secure::protocol::enums::ProtocolOpcode::PASEPake2;
use crate::secure::protocol::enums::{GeneralCode, ProtocolCode, ProtocolOpcode};
use crate::secure::protocol::message::ProtocolMessage;
use crate::secure::protocol::protocol_id::ProtocolID::ProtocolSecureChannel;
use crate::secure::session::{Exchange, UnencryptedSession};
use crate::tlv::structs::pake_1::Pake1;
use crate::tlv::structs::pake_2::Pake2;
use crate::tlv::structs::pake_3::Pake3;
use crate::tlv::structs::pbkdf_parameter_request::PBKDFParamRequest;
use crate::tlv::structs::pbkdf_parameter_response::PBKDFParamResponse;
use crate::tlv::tlv::TLV;
use crate::utils::MatterError;
use crate::utils::MatterLayer::Generic;
use crate::{build_simple_response, build_status_response, log_error, perform_validity_checks, process_message, START_TIME};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use std::collections::HashMap;
use std::io::Cursor;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::thread::JoinHandle;
use GeneralCode::Failure;

pub mod enums;
pub mod protocol;
pub mod message;
pub mod message_header;
pub mod message_flags;
pub mod security_flags;
pub mod message_extension;
pub mod message_builder;
pub mod session;

/// Message processing thread
pub(crate) fn start_processing_thread(receiver: Receiver<NetworkMessage>, outgoing_sender: Sender<NetworkMessage>) -> JoinHandle<()> {
    let mut exchange_map: HashMap<u16, Exchange> = Default::default();
    thread::Builder::new().name("Processing thread".to_string()).stack_size(50_000).spawn(move || {
        // let _reception_states: HashMap<u64, MessageReceptionState> = Default::default();
        // let _group_data_reception_states: HashMap<u64, MessageReceptionState> = Default::default();
        // let _group_control_reception_states: HashMap<u64, MessageReceptionState> = Default::default();

        loop {
            let message_to_process = receiver.recv();
            match message_to_process {
                Ok(network_message) => {
                    // Protocol validity checks for matter message...
                    if !perform_validity_checks(&network_message.message) {
                        log_error!("Failed validity checks...");
                        continue;
                    }
                    if let Err(error) = process_message(network_message, &outgoing_sender, &mut exchange_map) {
                        log_error!("Unable to process message: {:?}", error);
                    }
                }
                Err(error) => log_error!("Unable to receive the message {:?}", error)
            }
        }
    }).expect("Unable to start processing thread...")
}


pub(crate) fn process_unencrypted(session: &mut UnencryptedSession, matter_message: MatterMessage, protocol_message: ProtocolMessage) -> Result<NetworkMessage, MatterError> {
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
            let payload = Into::<TLV>::into(response).to_bytes();
            session.initiator_session_id = request.initiator_session_id;
            session.add_to_context(&protocol_message.payload);
            session.add_to_context(&payload);
            return Ok(build_simple_response(ProtocolOpcode::PBKDFParamResponse, protocol_message.exchange_id, &matter_message, &payload));
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
            return Ok(build_simple_response(PASEPake2, exchange_id, &matter_message, &payload));
        }
        ProtocolOpcode::PASEPake3 => {
            let pake_3 = Pake3::try_from(tlv)?;
            if let Some(confirmation) = &session.confirmation {
                if confirmation.cA != pake_3.c_a {
                    return Ok(
                        build_status_response(
                            Failure, ProtocolSecureChannel, InvalidParameter,
                            exchange_id, &matter_message,
                        )
                    );
                }
                session.timestamp = START_TIME.elapsed()?.as_secs();
                return Ok(
                    build_status_response(
                        GeneralCode::Success, ProtocolSecureChannel, ProtocolCode::SessionEstablishmentSuccess,
                        exchange_id, &matter_message,
                    )
                );
            }
        }
        _ => {
            todo!("Received OPCODE: {:?}", protocol_message.opcode);
        }
    }
    Err(MatterError::new(Generic, "Unable to process unencrypted session..."))
}