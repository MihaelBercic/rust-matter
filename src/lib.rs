use std::collections::HashMap;
use std::net::UdpSocket;
use std::sync::Arc;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::thread::JoinHandle;

use crate::network::network_message::NetworkMessage;
use crate::secure::enums::MatterDestinationID::Node;
use crate::secure::message::MatterMessage;
use crate::secure::message_builder::MatterMessageBuilder;
use crate::secure::protocol::communication::message_reception::MessageReceptionState;
use crate::secure::protocol::message::ProtocolMessage;
use crate::secure::protocol::message_builder::ProtocolMessageBuilder;

mod tests;
pub mod crypto;
pub mod mdns;
pub mod utils;
pub mod secure;
pub mod constants;
pub mod network;

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
fn start_processing_thread(receiver: Receiver<NetworkMessage>, _outgoing_sender: Sender<NetworkMessage>) -> JoinHandle<()> {
    thread::spawn(move || {
        let _reception_states: HashMap<u64, MessageReceptionState> = Default::default();
        let _group_data_reception_states: HashMap<u64, MessageReceptionState> = Default::default();
        let _group_control_reception_states: HashMap<u64, MessageReceptionState> = Default::default();

        loop {
            let message_to_process = receiver.recv();
            match message_to_process {
                Ok(network_message) => {
                    let _protocol_message = parse_protocol_message(&network_message.message);
                    println!("Processing the message {:?}", network_message.message);
                    process_message(network_message);
                    // A()
                    // B()
                    // C()
                    // D()
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
                    udp_socket.send_to(&network_message.message.as_bytes(), network_message.address).expect("U");
                }
                Err(_) => {}
            }
        }
    })
}

fn parse_protocol_message(matter_message: &MatterMessage) -> ProtocolMessage {
    let protocol_message = ProtocolMessage::try_from(&matter_message.payload[..]);
    match protocol_message {
        Ok(protocol_message) => protocol_message,
        Err(error) => panic!("Unable to parse the matter {:?}...", error)
    }
}

pub fn process_message(network_message: NetworkMessage) {
    let matter_message = network_message.message;
    let protocol_message = ProtocolMessage::try_from(&matter_message.payload[..]);
    match protocol_message {
        Ok(message) => {
            println!("Needs ack: {}", message.exchange_flags.needs_acknowledgement());
            if message.exchange_flags.needs_acknowledgement() {
                let protocol_message = ProtocolMessageBuilder::new()
                    .set_acknowledged_message_counter(message.acknowledged_message_counter)
                    .build();
                let matter_message = MatterMessageBuilder::new()
                    .set_destination(Node(matter_message.header.source_node_id.unwrap()))
                    .set_payload(&protocol_message.as_bytes()[..])
                    .build();
                let _response_message = NetworkMessage {
                    address: network_message.address,
                    message: matter_message,
                    retry_counter: 0,
                };
            }
        }
        Err(error) => println!("Yikes: {:?}", error)
    };
}


