use crate::network::network_message::NetworkMessage;
use crate::session::insecure::process_insecure;
use crate::session::secure::process_secure;
use crate::utils::MatterError;
use crate::{log_error, perform_validity_checks};
use byteorder::WriteBytesExt;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::thread::JoinHandle;

///
/// @author Mihael Berčič
/// @date 18. 9. 24
///
pub mod insecure;
pub mod secure;
pub mod protocol;
pub mod matter;
pub mod matter_message;
pub mod protocol_message;
pub mod counters;
pub mod message_reception;

/// Message processing thread
pub(crate) fn start_processing_thread(receiver: Receiver<NetworkMessage>, outgoing_sender: Sender<NetworkMessage>) -> JoinHandle<()> {
    thread::Builder::new().name("Processing thread".to_string()).stack_size(50 * 1024).spawn(move || {
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

fn process_message(network_message: NetworkMessage, outgoing_sender: &Sender<NetworkMessage>) -> Result<(), MatterError> {
    let matter_message = network_message.message;
    let mut message = if matter_message.header.is_insecure_unicast_session() {
        process_insecure(matter_message)?
    } else {
        process_secure(matter_message)?
    };
    message.address = network_message.address;
    outgoing_sender.send(message);
    Ok(())
}

pub enum SessionType {
    CASE,
    PASE,
}

#[derive(Clone, Debug)]
pub enum SessionRole {
    Prover,
    Verifier,
}