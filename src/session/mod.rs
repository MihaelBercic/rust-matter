use crate::constants::UNSPECIFIED_NODE_ID;
use crate::logging::color_red;
use crate::logging::color_reset;
use crate::logging::color_yellow;
use crate::network::network_message::NetworkMessage;
use crate::session::counters::{increase_counter, GLOBAL_UNENCRYPTED_COUNTER};
use crate::session::matter::builder::MatterMessageBuilder;
use crate::session::matter::enums::MatterDestinationID;
use crate::session::protocol::enums::SecureChannelProtocolOpcode;
use crate::session::protocol::interaction::enums::InteractionProtocolOpcode;
use crate::session::protocol::interaction::process_interaction_model;
use crate::session::protocol::process_secure_channel;
use crate::session::protocol::protocol_id::ProtocolID;
use crate::session::protocol_message::ProtocolMessage;
use crate::utils::{generic_error, MatterError};
use crate::SharedDevice;
use crate::{log_error, log_info, perform_validity_checks, SESSIONS};
use byteorder::WriteBytesExt;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::thread::JoinHandle;

pub mod counters;
mod device;
pub mod matter;
pub mod matter_message;
pub mod message_reception;
///
/// @author Mihael Berčič
/// @date 18. 9. 24
///
pub mod protocol;
pub mod protocol_message;
pub mod session;
pub use device::*;

/// Message processing thread
pub(crate) fn start_processing_thread(
    receiver: Receiver<NetworkMessage>,
    outgoing_sender: Sender<NetworkMessage>,
    device: SharedDevice,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name("Processing thread".to_string())
        .stack_size(100 * 1024)
        .spawn(move || loop {
            let message_to_process = receiver.recv();
            match message_to_process {
                Ok(network_message) => {
                    if !perform_validity_checks(&network_message.message) {
                        log_error!("Failed validity checks...");
                        continue;
                    }
                    if let Err(error) = process_message(network_message, &outgoing_sender, device.clone()) {
                        log_error!("Unable to process message: {:?}", error);
                    }
                }
                Err(error) => log_error!("Unable to receive the message {:?}", error),
            }
        })
        .expect("Unable to start processing thread...")
}

fn process_message(network_message: NetworkMessage, outgoing_sender: &Sender<NetworkMessage>, device: SharedDevice) -> Result<(), MatterError> {
    let mut matter_message = network_message.message;
    let Ok(session_map) = &mut SESSIONS.lock() else {
        return Err(generic_error("Unable to obtain active sessions map!"));
    };

    if !session_map.contains_key(&matter_message.header.session_id) {
        if let Some(removed) = session_map.remove(&0) {
            session_map.insert(matter_message.header.session_id, removed);
        }
    }

    let mut session = session_map.entry(matter_message.header.session_id).or_insert(Default::default());
    session.decode(&mut matter_message)?;
    let source_node_id = matter_message.header.source_node_id.unwrap_or(UNSPECIFIED_NODE_ID);
    let protocol_message = ProtocolMessage::try_from(&matter_message.payload[..])?;
    let debug_opcode = match protocol_message.protocol_id {
        ProtocolID::ProtocolSecureChannel => format!("{:?}", SecureChannelProtocolOpcode::from(protocol_message.opcode)),
        ProtocolID::ProtocolInteractionModel => format!("{:?}", InteractionProtocolOpcode::from(protocol_message.opcode)),
        _ => todo!("Not implemented protocol yet..."),
    };

    log_info!(
        "{color_red}|{:?}|{color_yellow}{}|{color_reset}",
        &protocol_message.protocol_id,
        debug_opcode
    );
    let mut device = device.lock().unwrap();

    let mut builder = match protocol_message.protocol_id {
        ProtocolID::ProtocolSecureChannel => process_secure_channel(&matter_message, protocol_message, source_node_id, &mut session, &mut device),
        ProtocolID::ProtocolInteractionModel => process_interaction_model(&matter_message, protocol_message, session, &mut device),
        ProtocolID::ProtocolBdx => todo!("Not yet implemented"),
        ProtocolID::ProtocolUserDirectedCommissioning => todo!("Not yet implemented"),
        ProtocolID::ProtocolForTesting => todo!("Not yet implemented"),
    }?;

    session.message_counter = if matter_message.header.is_insecure_unicast_session() {
        increase_counter(&GLOBAL_UNENCRYPTED_COUNTER)
    } else {
        matter_message.header.message_counter + 1
    };
    let payload: Vec<u8> = builder.build().into();
    let mut message = MatterMessageBuilder::new()
        .set_session_id(if matter_message.header.is_insecure_unicast_session() {
            0
        } else {
            session.peer_session_id
        })
        .set_destination(MatterDestinationID::Node(source_node_id))
        .set_counter(session.message_counter)
        .set_payload(&payload)
        .build();
    session.encode(&mut message);
    let message = NetworkMessage {
        address: network_message.address,
        message,
        retry_counter: 0,
    };
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
