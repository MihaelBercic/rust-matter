use crate::logging::*;
use crate::network::network_message::NetworkMessage;
use crate::session::insecure::process_insecure;
use crate::session::protocol::enums::ProtocolOpcode;
use crate::session::protocol_message::ProtocolMessage;
use crate::tlv::structs::status_report;
use crate::utils::MatterLayer::Transport;
use crate::utils::{generic_error, MatterError};
use crate::{log_error, log_info, perform_validity_checks, ENCRYPTED_SESSIONS};
use byteorder::WriteBytesExt;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::thread::JoinHandle;

///
/// @author Mihael Berčič
/// @date 18. 9. 24
///
pub(crate) mod insecure;
pub(crate) mod secure;
pub(crate) mod protocol;
pub(crate) mod matter;
pub(crate) mod matter_message;
pub(crate) mod protocol_message;

const UNSPECIFIED_NODE_ID: u64 = 0x0000_0000_0000_0000;
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

fn process_message(network_message: NetworkMessage, outgoing_sender: &Sender<NetworkMessage>) -> Result<(), MatterError> {
    let matter_message = network_message.message;
    if matter_message.header.is_insecure_unicast_session() {
        let protocol_message = ProtocolMessage::try_from(&matter_message.payload[..])?;
        log_info!("🔓\t{color_red}|{:?}|{color_blue}{:?}|{color_reset} message received.", &protocol_message.protocol_id, &protocol_message.opcode);

        match protocol_message.opcode {
            ProtocolOpcode::StatusReport => {
                let status_report = status_report::StatusReport::try_from(protocol_message);
                let representation = format!("{:?}", status_report);
                return Err(MatterError::Custom(Transport, representation));
            }
            ProtocolOpcode::MRPStandaloneAcknowledgement => {
                // TODO: Remove from retransmission...
                return Ok(());
            }
            _ => {}
        }
        let mut response = process_insecure(matter_message, protocol_message)?;
        response.address = network_message.address;
        outgoing_sender.send(response);
    } else {
        let Ok(session_map) = &mut ENCRYPTED_SESSIONS.lock() else {
            return Err(generic_error("Unable to lock ENCRYPTED_SESSIONS"));
        };
        let Some(session) = session_map.get_mut(&matter_message.header.session_id) else {
            return Err(generic_error("No session found"));
        };
        let decoded = session.decode(&matter_message)?;
        let protocol_message = ProtocolMessage::try_from(&decoded[..])?;
        log_info!("🔐\t{color_red}|{:?}|{color_blue}{:?}|{color_reset} message received.", &protocol_message.protocol_id, &protocol_message.opcode);

        // process secure
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


pub enum SessionType {
    CASE,
    PASE,
}

#[derive(Clone, Debug)]
pub enum SessionRole {
    Prover,
    Verifier,
}