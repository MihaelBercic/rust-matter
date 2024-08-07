use std::collections::HashMap;
use std::io::Cursor;
use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::thread::JoinHandle;

use crate::network::network_message::NetworkMessage;
use crate::secure::enums::{MatterDestinationID, MatterSessionType};
use crate::secure::enums::MatterDestinationID::Group;
use crate::secure::message::MatterMessage;
use crate::secure::message_builder::MatterMessageBuilder;
use crate::secure::protocol::communication::counters::{GLOBAL_UNENCRYPTED_COUNTER, increase_counter};
use crate::secure::protocol::communication::message_reception::MessageReceptionState;
use crate::secure::protocol::enums::ProtocolOpcode;
use crate::secure::protocol::enums::ProtocolOpcode::MRPStandaloneAcknowledgement;
use crate::secure::protocol::message::ProtocolMessage;
use crate::secure::protocol::message_builder::ProtocolMessageBuilder;
use crate::tlv::structs::pake_1::Pake1;
use crate::tlv::structs::pbkdf_param_request::PBKDFParamRequest;
use crate::tlv::structs::pbkdf_param_response::PBKDFParamResponse;
use crate::tlv::tlv::TLV;

mod tests;
pub mod crypto;
pub mod mdns;
pub mod utils;
pub mod secure;
pub mod constants;
pub mod network;
pub mod tlv;

/// Starts the matter protocol advertisement (if needed) and starts running the matter protocol based on the settings provided.
pub fn start() {
    let udp_socket = Arc::new(UdpSocket::bind("[::]:0").expect("Unable to bind to tcp..."));
    let (processing_sender, processing_receiver) = channel::<NetworkMessage>();
    let (outgoing_sender, outgoing_receiver) = channel::<NetworkMessage>();

    mdns::service::start_advertising(&udp_socket);
    start_listening_thread(processing_sender.clone(), udp_socket.clone());
    start_outgoing_thread(outgoing_receiver, udp_socket);
    start_processing_thread(processing_receiver, outgoing_sender).join().expect("Unable to start the thread for processing messages...");
}

/// Thread that is listening on the UDP socket for any incoming messages...
fn start_listening_thread(processing_sender: Sender<NetworkMessage>, udp_socket: Arc<UdpSocket>) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut buffer = [0u8; 1000];
        println!("Listening on: {:?}", udp_socket.local_addr());
        loop {
            let (size, sender) = udp_socket.recv_from(&mut buffer).unwrap();
            println!("Received {} data on UDP socket...", size);
            match MatterMessage::try_from(&buffer[..size]) {
                Ok(matter_message) => {
                    let network_message = NetworkMessage { address: sender, message: matter_message, retry_counter: 0 };
                    processing_sender.send(network_message).unwrap()
                }
                Err(error) => println!("Yikes {:?}", error)
            }
        }
    })
}

/// Message processing thread
fn start_processing_thread(receiver: Receiver<NetworkMessage>, outgoing_sender: Sender<NetworkMessage>) -> JoinHandle<()> {
    thread::spawn(move || {
        let _reception_states: HashMap<u64, MessageReceptionState> = Default::default();
        let _group_data_reception_states: HashMap<u64, MessageReceptionState> = Default::default();
        let _group_control_reception_states: HashMap<u64, MessageReceptionState> = Default::default();

        loop {
            let message_to_process = receiver.recv();
            match message_to_process {
                Ok(network_message) => {
                    let matter_message = &network_message.message;
                    let message = ProtocolMessage::try_from(&matter_message.payload[..]);
                    if !perform_validity_checks(&matter_message) { continue; }
                    if let Ok(message) = message {
                        let tlv = TLV::try_from_cursor(&mut Cursor::new(&message.payload));
                        if let Ok(tlv) = tlv {
                            match message.opcode {
                                ProtocolOpcode::PBKDFParamRequest => {
                                    let pbdkf = PBKDFParamRequest::try_from(tlv);
                                    if let Ok(request) = pbdkf {
                                        let response = PBKDFParamResponse::build_for(&request);
                                        println!("Response built...");
                                        if let Ok(response) = response {
                                            let tlv: TLV = response.into();
                                            let bytes = tlv.to_bytes();
                                            let message = ProtocolMessageBuilder::new()
                                                .set_needs_acknowledgement(true)
                                                .set_exchange_id(message.exchange_id)
                                                .set_opcode(ProtocolOpcode::PBKDFParamResponse)
                                                .set_payload(&bytes)
                                                .set_acknowledged_message_counter(matter_message.header.message_counter)
                                                .build();
                                            let response_matter = MatterMessageBuilder::new()
                                                .set_destination(MatterDestinationID::Node(matter_message.header.source_node_id.unwrap()))
                                                .set_counter(increase_counter(&GLOBAL_UNENCRYPTED_COUNTER))
                                                .set_payload(&message.to_bytes())
                                                .build();
                                            let network_message = NetworkMessage {
                                                address: network_message.address,
                                                message: response_matter,
                                                retry_counter: 0,
                                            };
                                            outgoing_sender.send(network_message).expect("Unable to send network message...");
                                        }
                                    }
                                    // create response and send... (set ack counter)...
                                }
                                ProtocolOpcode::PASEPake1 => {
                                    let test_salt = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];
                                    let iterations = 1000;
                                    let pake = Pake1::try_from(tlv).unwrap();
                                    println!("test salt = {:?}", hex::encode(test_salt));
                                    println!("iterations = {:?}", iterations);
                                    // println!("pB = {:?}", hex::encode(spake.pB));
                                }
                                _ => {
                                    s_a(&network_message, &message, &outgoing_sender);
                                    println!("Received OPCODE: {:?}", ProtocolOpcode::from(message.opcode));
                                }
                            }
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
                }
                Err(error) => println!("Unable to receive the message {:?}", error)
            }
        }
    })
}

/// Outgoing message processing thread
fn start_outgoing_thread(receiver: Receiver<NetworkMessage>, udp_socket: Arc<UdpSocket>) -> JoinHandle<()> {
    thread::spawn(move || {
        loop {
            let outgoing_message = receiver.recv();
            match outgoing_message {
                Ok(network_message) => {
                    println!("Sending a network message through the UDP to {:?}", network_message.address);
                    udp_socket.send_to(&network_message.message.as_bytes(), network_message.address).expect("U");
                }
                Err(_) => {}
            }
        }
    })
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

fn s_a(network_message: &NetworkMessage, protocol_message: &ProtocolMessage, outgoing: &Sender<NetworkMessage>) {
    let counter = network_message.message.header.message_counter;
    let destination = network_message.message.header.source_node_id.unwrap();
    let address = network_message.address;
    let p = ProtocolMessageBuilder::new()
        .set_acknowledged_message_counter(counter)
        .set_opcode(MRPStandaloneAcknowledgement)
        .set_exchange_id(protocol_message.exchange_id)
        .build();
    let matter_message = MatterMessageBuilder::new()
        .set_counter(increase_counter(&GLOBAL_UNENCRYPTED_COUNTER))
        .set_session_type(MatterSessionType::Unicast)
        .set_destination(MatterDestinationID::Node(destination))
        .set_payload(&p.to_bytes())
        .build();
    println!("Sent counter {:?}...", matter_message.header.message_counter);

    let network_message = NetworkMessage {
        address,
        message: matter_message,
        retry_counter: 0,
    };
    outgoing.send(network_message).expect("Unable to send network message...");
}
