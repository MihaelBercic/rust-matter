use std::collections::HashMap;
use std::net::UdpSocket;
use std::ops::Add;
use std::sync::Arc;
use std::sync::mpsc::channel;
use std::thread;

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

pub trait ByteEncodable {
    fn from_bytes(bytes: &[u8]) -> Self;
    fn to_bytes(&self) -> Vec<u8>;
}

pub fn start() {
    let reception_states: HashMap<u64, MessageReceptionState> = Default::default();
    let group_data_reception_states: HashMap<u64, MessageReceptionState> = Default::default();
    let group_control_reception_states: HashMap<u64, MessageReceptionState> = Default::default();

    let udp_socket = Arc::new(UdpSocket::bind("[::]:0").expect("Unable to bind to tcp..."));
    mdns::service::start_advertising(&udp_socket);

    let (processing_sender, processing_receiver) = channel::<NetworkMessage>();
    let (outgoing_sender, outgoing_receiver) = channel::<NetworkMessage>();


    let udp_socket_clone = udp_socket.clone();
    let processing_sender_clone = processing_sender.clone();
    /// Thread that is listening on the UDP socket for any incoming messages...
    thread::spawn(move || {
        let mut buffer = [0u8; 1000];
        println!("Listening on: {:?}", udp_socket_clone.local_addr());
        loop {
            let (size, sender) = udp_socket_clone.recv_from(&mut buffer).unwrap();
            println!("Received {} data on UDP socket...", size);
            match MatterMessage::try_from(&buffer[..size]) {
                Ok(matter_message) => {
                    let network_message = NetworkMessage { address: sender, message: matter_message, retry_counter: 0 };
                    processing_sender_clone.send(network_message).unwrap()
                }
                Err(error) => println!("Yikes {:?}", error)
            }
        }
    });

    /// Outgoing message processing thread
    thread::spawn(move || {
        loop {
            let outgoing_message = outgoing_receiver.recv();
            match outgoing_message {
                Ok(network_message) => {
                    udp_socket.send_to(&network_message.message.as_bytes(), network_message.address).expect("U");
                }
                Err(_) => {}
            }
        }
    });

    /// Message processing thread
    thread::spawn(move || {
        loop {
            let message_to_process = processing_receiver.recv();
            match message_to_process {
                Ok(network_message) => {
                    println!("Processing the message {:?}", network_message.message);
                    // A()
                    // B()
                    // C()
                    // D()
                    // outgoing_sender.send();
                }
                Err(error) => println!("Unable to receive the message {:?}", error)
            }
        }
    }).join().expect("Unable to start the thread for processing messages...");
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
                let response_message = NetworkMessage {
                    address: network_message.address,
                    message: matter_message,
                    retry_counter: 0,
                };
            }
        }
        Err(error) => println!("Yikes: {:?}", error)
    };
}


