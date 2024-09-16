use crate::network::network_message::NetworkMessage;
use crate::secure::message::MatterMessage;
use crate::{log_error, log_info};
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
pub(crate) fn start_listening_thread(processing_sender: Sender<NetworkMessage>, udp_socket: Arc<UdpSocket>) -> JoinHandle<()> {
    thread::Builder::new().name("Listening thread".to_string()).stack_size(30_000).spawn(move || {
        let mut buffer = [0u8; 5000];
        log_info!("Listening on: {}", udp_socket.local_addr().unwrap().port());
        loop {
            match udp_socket.recv_from(&mut buffer) {
                Ok((size, sender)) => {
                    // log_info!("Received {} data on UDP socket...", size);
                    match MatterMessage::try_from(&buffer[..size]) {
                        Ok(matter_message) => {
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
                        // log_debug!("Sending a network message through the UDP to {}", network_message.address.to_string());
                        udp_socket.send_to(&network_message.message.to_bytes(), recipient).unwrap();
                    }
                }
                Err(_) => {}
            }
        }
    }).expect("Unable to start outgoing thread...")
}
