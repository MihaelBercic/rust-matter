use crate::network::network_message::NetworkMessage;
use crate::session::counters::GLOBAL_UNENCRYPTED_COUNTER;
use crate::session::matter::enums::MatterDestinationID;
use crate::session::matter_message::MatterMessage;
use crate::session::protocol::enums::SecureChannelProtocolOpcode;
use crate::session::protocol::message_builder::ProtocolMessageBuilder;
use crate::session::protocol::protocol_id::ProtocolID;
use crate::{build_network_message, log_error, log_info};
use std::net::UdpSocket;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;

///
/// @author Mihael Berčič
/// @date 28. 7. 24
///

pub mod enums;
pub mod network_message;


/// Thread that is listening on the UDP socket for any incoming messages...
pub(crate) fn start_listening_thread(processing_sender: Sender<NetworkMessage>, udp_socket: Arc<UdpSocket>, outgoing_sender: Sender<NetworkMessage>) -> JoinHandle<()> {
    thread::Builder::new().name("Listening thread".to_string()).stack_size(30_000).spawn(move || {
        let mut buffer = [0u8; 5000];
        let mut history = vec![];
        log_info!("Listening on: {}", udp_socket.local_addr().unwrap().port());
        loop {
            match udp_socket.recv_from(&mut buffer) {
                Ok((size, sender)) => {
                    // log_info!("Received {} data on UDP socket...", size);
                    match MatterMessage::try_from(&buffer[..size]) {
                        Ok(matter_message) => {
                            let message_id = matter_message.header.message_counter;
                            if history.contains(&message_id) {
                                let Some(destination) = matter_message.header.source_node_id else {
                                    continue;
                                };

                                log_error!("Already seen message...");
                                let proto = ProtocolMessageBuilder::new()
                                    .set_acknowledged_message_counter(matter_message.header.message_counter)
                                    .set_opcode(SecureChannelProtocolOpcode::MRPStandaloneAcknowledgement as u8)
                                    .set_protocol(ProtocolID::ProtocolSecureChannel)
                                    .build();
                                let nm = build_network_message(proto, &GLOBAL_UNENCRYPTED_COUNTER, MatterDestinationID::Node(destination));
                                outgoing_sender.send(nm);
                                continue;
                            }
                            history.push(message_id);
                            let network_message = NetworkMessage { address: Some(sender), message: matter_message, retry_counter: 0 };
                            processing_sender.send(network_message).unwrap()
                        }
                        Err(error) => {
                            println!("oopsie");
                            log_error!("Yikes {:?}", error);
                        }
                    }
                }
                Err(error) => {
                    log_error!("Unable to receive a packet: {:?}", error);
                }
            }
        }
    }).expect("Unable to start a listening thread...")
}


/// Outgoing message processing thread
pub(crate) fn start_outgoing_thread(receiver: Receiver<NetworkMessage>, udp_socket: Arc<UdpSocket>) -> JoinHandle<()> {
    thread::Builder::new().name("Outgoing thread".to_string()).stack_size(10_000).spawn(move || {
        loop {
            let outgoing_message = receiver.recv();
            match outgoing_message {
                Ok(network_message) => {
                    if let Some(recipient) = network_message.address {
                        // log_debug!("Sending a network message through the UDP to {}", recipient.to_string());
                        udp_socket.send_to(&network_message.message.to_bytes(), recipient).unwrap();
                    }
                }
                Err(_) => {}
            }
        }
    }).expect("Unable to start outgoing thread...")
}
