use std::sync::mpsc::Sender;

use counters::{increase_counter, GLOBAL_UNENCRYPTED_COUNTER};
use device::{SharedDevice, SESSIONS};
use matter_message::builder::MatterMessageBuilder;
use protocol_message::{ProtocolID, ProtocolMessage, SecureChannelProtocolOpcode};
use session::{
    interaction_model::{enums::InteractionProtocolOpcode, process_interaction},
    secure_channel::process_secure,
};

use crate::{
    constants::UNSPECIFIED_NODE_ID,
    logging::*,
    network::network_message::NetworkMessage,
    utils::{bail_generic, MatterError},
};

pub(crate) mod counters;
pub(crate) mod device;
pub(crate) mod enums;
pub(crate) mod matter_message;
pub(crate) mod message_reception;
pub(crate) mod protocol_message;
pub(crate) mod session;

fn process_incoming(network_message: NetworkMessage, outgoing_sender: &Sender<NetworkMessage>, device: SharedDevice) -> Result<(), MatterError> {
    let mut matter_message = network_message.message;
    let Ok(session_map) = &mut SESSIONS.lock() else {
        bail_generic!("Unable to obtain active sessions map!");
    };

    // If the session is not in our map and we have a new session being setup (0), replace the session with id = 0 to the new id.
    // if !session_map.contains_key(&matter_message.header.session_id) {
    //     if let Some(removed) = session_map.remove(&0) {
    //         session_map.insert(matter_message.header.session_id, removed);
    //     }
    // }

    // log_info!("Attempting to find a session with the id: {}", matter_message.header.session_id);
    let old_session_id = matter_message.header.session_id;
    let new_session_id = {
        log_debug!("Did we find session? {}", session_map.contains_key(&matter_message.header.session_id));
        let session = session_map.entry(matter_message.header.session_id).or_insert(Default::default());
        session.decode(&mut matter_message)?;

        let source_node_id = matter_message.header.source_node_id.unwrap_or(UNSPECIFIED_NODE_ID);
        let protocol_message = ProtocolMessage::try_from(&matter_message.payload[..])?;
        let debug_opcode = match protocol_message.protocol_id {
            ProtocolID::ProtocolSecureChannel => format!("{:?}", SecureChannelProtocolOpcode::from(protocol_message.opcode)),
            ProtocolID::ProtocolInteractionModel => format!("{:?}", InteractionProtocolOpcode::from(protocol_message.opcode)),
            _ => todo!("Not implemented protocol yet..."),
        };

        log_info!("{color_red}{:?} \u{27F6} {color_yellow}{}{color_reset}", &protocol_message.protocol_id, debug_opcode);
        let mut device = device.lock().unwrap();
        let builders = match protocol_message.protocol_id {
            ProtocolID::ProtocolSecureChannel => process_secure(source_node_id, protocol_message, session, &mut device),
            ProtocolID::ProtocolInteractionModel => process_interaction(),
            _ => todo!("Not yet implemented."),
        };

        if let Ok(builders) = builders {
            let builders = builders.into_iter().map(|builder| builder.set_acknowledged_message_counter(matter_message.header.message_counter));
            for builder in builders {
                let payload: Vec<u8> = builder.build().into();
                session.message_counter = if matter_message.header.is_insecure_unicast_session() {
                    increase_counter(&GLOBAL_UNENCRYPTED_COUNTER)
                } else {
                    matter_message.header.message_counter + 1
                };
                let mut message = MatterMessageBuilder::new()
                    .set_session_id(if matter_message.header.is_insecure_unicast_session() { 0 } else { session.peer_session_id })
                    .set_destination(enums::DestinationID::Node(source_node_id))
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
            }
        } else {
            todo!("Add StatusReport send!")
        }
        session.session_id
    };
    if new_session_id != old_session_id {
        let removed = session_map.remove(&old_session_id).unwrap();
        session_map.insert(new_session_id, removed);
    }
    Ok(())
}
