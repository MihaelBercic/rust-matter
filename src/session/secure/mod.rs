use crate::network::network_message::NetworkMessage;
use crate::session::matter::builder::MatterMessageBuilder;
use crate::session::matter_message::MatterMessage;
use crate::session::protocol::interaction::process_interaction_model;
use crate::session::protocol::protocol_id::ProtocolID;
use crate::session::protocol_message::ProtocolMessage;
use crate::utils::{generic_error, MatterError};
use crate::ENCRYPTED_SESSIONS;

pub(crate) mod session;

pub fn process_secure(message: MatterMessage) -> Result<NetworkMessage, MatterError> {
    let session_id = message.header.session_id;
    let Ok(session_map) = &mut ENCRYPTED_SESSIONS.lock() else {
        return Err(generic_error("Unable to lock ENCRYPTED_SESSIONS"));
    };
    let Some(session) = session_map.get_mut(&session_id) else {
        return Err(generic_error("No session found"));
    };
    let decoded = session.decode(&message)?;
    let protocol_message = ProtocolMessage::try_from(&decoded[..])?;
    let mut response = match protocol_message.protocol_id {
        ProtocolID::ProtocolInteractionModel => process_interaction_model(message.clone(), protocol_message),
        _ => {
            return Err(generic_error(&format!("Not yet implemented {:?}", protocol_message.protocol_id)))
        }
        // ProtocolID::ProtocolBdx => {}
        // ProtocolID::ProtocolUserDirectedCommissioning => {}
        // ProtocolID::ProtocolForTesting => {}
    }?;
    session.message_counter = message.header.message_counter + 1;
    let payload: Vec<u8> = response.build().into();
    let mut matter = MatterMessageBuilder::reuse(message)
        .set_session_id(session.peer_session_id)
        .set_counter(session.message_counter)
        .set_payload(&payload)
        .build();
    session.encode(&mut matter);
    Ok(NetworkMessage {
        address: None,
        message: matter,
        retry_counter: 0,
    })
    // encode...

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