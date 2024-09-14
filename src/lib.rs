#![allow(unused)]
#![allow(dead_code)]

use crate::crypto::constants::{CONTEXT_PREFIX_VALUE, CRYPTO_PUBLIC_KEY_SIZE_BYTES};
use crate::crypto::hash_message;
use crate::crypto::spake::values::Values::SpakeVerifier;
use crate::crypto::spake::Spake2P;
use crate::logging::{color_blue, color_red, color_reset};
use crate::mdns::enums::{CommissionState, DeviceType};
use crate::network::network_message::NetworkMessage;
use crate::secure::enums::MatterDestinationID;
use crate::secure::enums::MatterDestinationID::Group;
use crate::secure::message::MatterMessage;
use crate::secure::message_builder::MatterMessageBuilder;
use crate::secure::protocol::communication::counters::{increase_counter, GLOBAL_UNENCRYPTED_COUNTER};
use crate::secure::protocol::enums::ProtocolOpcode;
use crate::secure::protocol::enums::ProtocolOpcode::{MRPStandaloneAcknowledgement, PASEPake2, StatusReport};
use crate::secure::protocol::message::ProtocolMessage;
use crate::secure::protocol::message_builder::ProtocolMessageBuilder;
use crate::secure::session::Exchange;
use crate::tlv::structs::pake_1::Pake1;
use crate::tlv::structs::pake_2::Pake2;
use crate::tlv::structs::pbkdf_parameter_request::PBKDFParamRequest;
use crate::tlv::structs::pbkdf_parameter_response::PBKDFParamResponse;
use crate::tlv::tlv::TLV;
use crate::utils::MatterError;
use crate::utils::MatterLayer::Transport;
use byteorder::WriteBytesExt;
use p256::elliptic_curve::group::GroupEncoding;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use std::collections::HashMap;
use std::io::Cursor;
use std::net::{Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;

mod tests;
pub mod crypto;
pub mod mdns;
pub mod utils;
pub mod secure;
pub mod constants;
pub mod network;
pub mod tlv;
pub mod logging;

/// Starts the matter protocol advertisement (if needed) and starts running the matter protocol based on the settings provided.
pub fn start(device_info: &MDNSDeviceInformation, interface: NetworkInterface) {
    let udp_socket = Arc::new(UdpSocket::bind(format!("[::%{}]:0", interface.index)).expect("Unable to bind to tcp..."));
    let (processing_sender, processing_receiver) = channel::<NetworkMessage>();
    let (outgoing_sender, outgoing_receiver) = channel::<NetworkMessage>();

    mdns::start_advertising(&udp_socket, device_info, &interface);
    log_info!("Starting listening thread...");
    start_listening_thread(processing_sender.clone(), udp_socket.clone());
    log_info!("Starting outgoing thread...");
    start_outgoing_thread(outgoing_receiver, udp_socket);
    log_info!("Starting processing thread...");
    start_processing_thread(processing_receiver, outgoing_sender).join().expect("Unable to start the thread for processing messages...");
}

/// Thread that is listening on the UDP socket for any incoming messages...
fn start_listening_thread(processing_sender: Sender<NetworkMessage>, udp_socket: Arc<UdpSocket>) -> JoinHandle<()> {
    thread::Builder::new().name("Listening thread".to_string()).stack_size(30_000).spawn(move || {
        let mut buffer = [0u8; 9000];
        log_info!("Listening on: {}", udp_socket.local_addr().unwrap().port());
        loop {
            match udp_socket.recv_from(&mut buffer) {
                Ok((size, sender)) => {
                    // log_info!("Received {} data on UDP socket...", size);
                    match MatterMessage::try_from(&buffer[..size]) {
                        Ok(matter_message) => {
                            let network_message = NetworkMessage { address: sender, message: matter_message, retry_counter: 0 };
                            processing_sender.send(network_message).unwrap()
                        }
                        Err(error) => log_error!("Yikes {:?}", error)
                    }
                }
                Err(error) => {
                    log_error!("Unable to receive a packet: {:?}", error);
                }
            }
        }
    }).expect("Unable to start a listening thread...")
}

/// Message processing thread
fn start_processing_thread(receiver: Receiver<NetworkMessage>, outgoing_sender: Sender<NetworkMessage>) -> JoinHandle<()> {
    let mut exchange_map: HashMap<u16, Exchange> = Default::default();
    thread::Builder::new().name("Processing thread".to_string()).stack_size(50_000).spawn(move || {
        // let _reception_states: HashMap<u64, MessageReceptionState> = Default::default();
        // let _group_data_reception_states: HashMap<u64, MessageReceptionState> = Default::default();
        // let _group_control_reception_states: HashMap<u64, MessageReceptionState> = Default::default();

        loop {
            let message_to_process = receiver.recv();
            match message_to_process {
                Ok(network_message) => {
                    if let Err(error) = process_message(network_message, &outgoing_sender, &mut exchange_map) {
                        log_error!("Unable to process message: {:?}", error);
                    }
                }
                Err(error) => log_error!("Unable to receive the message {:?}", error)
            }
        }
    }).expect("Unable to start processing thread...")
}

fn process_message(network_message: NetworkMessage, outgoing_sender: &Sender<NetworkMessage>, exchange_map: &mut HashMap<u16, Exchange>) -> Result<(), MatterError> {
    let matter_message = network_message.message;
    let protocol_message = ProtocolMessage::try_from(&matter_message.payload[..])?;
    if !perform_validity_checks(&matter_message) { return Err(MatterError::new(Transport, "Failed validity checks.")); }
    let mut e = exchange_map.entry(protocol_message.exchange_id).or_insert(Exchange::new(protocol_message.exchange_id));
    if protocol_message.opcode == StatusReport {
        let status_report = tlv::structs::status_report::StatusReport::try_from(protocol_message);
        let representation = format!("{:?}", status_report);
        return Err(MatterError::Custom(Transport, representation));
    }
    // TODO: mark as acknowledged from message.acknowledged_message_counter
    if protocol_message.opcode == MRPStandaloneAcknowledgement {
        log_debug!("Received MRP acknowledgement for {}", protocol_message.acknowledged_message_counter.unwrap());
        return Ok(());
    }
    let tlv = TLV::try_from_cursor(&mut Cursor::new(&protocol_message.payload))?;
    log_info!("{color_red}[{:?}]{color_blue}[{:?}]{color_reset} message received.", protocol_message.protocol_id, protocol_message.opcode);
    match protocol_message.opcode {
        ProtocolOpcode::PBKDFParamRequest => {
            let request = PBKDFParamRequest::try_from(tlv)?;
            let response = PBKDFParamResponse::build_for(&request)?;
            e.pbkdf_request = Some(request);                 // TODO: optimize
            e.request_bytes = protocol_message.payload.to_vec();
            e.pbkdf_response = Some(response.clone());       // TODO: optimize
            let tlv: TLV = response.into();
            let payload = tlv.to_bytes();
            send_response(network_message.address, &protocol_message, &matter_message, &outgoing_sender, ProtocolOpcode::PBKDFParamResponse, &payload);
        }
        ProtocolOpcode::PASEPake1 => {
            let test_salt = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];
            let iterations = 1000;
            let pake = Pake1::try_from(tlv)?;
            let spake = Spake2P::new();
            let prover = Spake2P::compute_prover(20202021, &test_salt, iterations);
            let verifier = Spake2P::compute_verifier(20202021, &test_salt, iterations);
            let p_b: [u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES] = spake.compute_public_verifier(&verifier.w0)?.to_encoded_point(false).as_bytes().try_into().unwrap();

            let request_tlv: TLV = e.clone().pbkdf_request.unwrap().into();
            let response_tlv: TLV = e.clone().pbkdf_response.unwrap().into();
            let mut context = vec![];
            context.extend_from_slice(&CONTEXT_PREFIX_VALUE);
            context.extend_from_slice(&e.request_bytes);
            context.extend_from_slice(&response_tlv.to_bytes());
            let context = hash_message(&context);

            let mut transcript = spake.compute_transcript(&context, &[], &[], SpakeVerifier(verifier), &pake.p_a, &p_b);
            let confirmation = spake.compute_confirmation_values(&transcript, &pake.p_a, &p_b, 256);

            let pake2 = Pake2 { p_b, c_b: confirmation.cB };
            let pake_tlv: TLV = pake2.into();
            let payload = pake_tlv.to_bytes();
            send_response(network_message.address, &protocol_message, &matter_message, &outgoing_sender, PASEPake2, &payload);
        }
        ProtocolOpcode::PASEPake3 => {}
        _ => {
            todo!("Received OPCODE: {:?}", protocol_message.opcode);
        }
    }

    /*
    ✅ validity_checks(...);
    obtain_keys(...)
    if keys {
       process_privacy(...)
       process_security(...)
    }
    process_counter(...);
    process_reliability(...);
    if unicast {
       set_session_timestamp
       set_active_timestamp
    }

    // Move to Exchange Message Processing
    */
    Ok(())
}

/// Outgoing message processing thread
fn start_outgoing_thread(receiver: Receiver<NetworkMessage>, udp_socket: Arc<UdpSocket>) -> JoinHandle<()> {
    thread::Builder::new().name("Outgoing thread".to_string()).stack_size(10_000).spawn(move || {
        loop {
            let outgoing_message = receiver.recv();
            match outgoing_message {
                Ok(network_message) => {
                    // log_debug!("Sending a network message through the UDP to {}", network_message.address.to_string());
                    udp_socket.send_to(&network_message.message.to_bytes(), network_message.address).unwrap();
                }
                Err(_) => {}
            }
        }
    }).expect("Unable to start outgoing thread...")
}

fn perform_validity_checks(message: &MatterMessage) -> bool {
    let header = &message.header;
    let unicast_check = header.is_secure_unicast_session() && matches!(header.destination_node_id, Some(Group(_)));
    let path_check = header.destination_node_id.is_none() || header.source_node_id.is_none();
    let group_check = header.is_group_session() && path_check;

    if header.flags.version() != 0
        || unicast_check
        || group_check {
        return false;
    }
    true
}

fn send_response(address: SocketAddr, protocol_message: &ProtocolMessage, matter_message: &MatterMessage, outgoing: &Sender<NetworkMessage>, opcode: ProtocolOpcode, payload: &[u8]) {
    let message = ProtocolMessageBuilder::new()
        .set_needs_acknowledgement(true)
        .set_exchange_id(protocol_message.exchange_id)
        .set_opcode(opcode) //opcode)
        .set_payload(payload)
        .set_acknowledged_message_counter(matter_message.header.message_counter)
        .build();
    let x = message.to_bytes();
    let response_matter = MatterMessageBuilder::new()
        .set_destination(MatterDestinationID::Node(matter_message.header.source_node_id.unwrap()))
        .set_counter(increase_counter(&GLOBAL_UNENCRYPTED_COUNTER))
        .set_payload(&x)
        .build();
    let network_message = NetworkMessage {
        address,
        message: response_matter,
        retry_counter: 0,
    };
    outgoing.send(network_message);
}

pub struct MDNSDeviceInformation {
    pub ip: Ipv6Addr,
    pub mac: [u8; 6],
    pub device_name: String,
    pub device_type: DeviceType,
    pub discriminator: u16, // Still don't know how this is supposed to be computed.
    pub commission_state: CommissionState,
    pub vendor_id: u16,
    pub product_id: u16,
}

pub struct NetworkInterface {
    pub index: u32,
    pub do_custom: bool,
}