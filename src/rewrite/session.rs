use byteorder::{WriteBytesExt, LE};
use ccm::aead::Payload;
use enums::MatterDestinationID;
use setup::{CaseSessionSetup, SessionSetup};

use crate::{
    constants::UNSPECIFIED_NODE_ID,
    crypto::{
        constants::CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES,
        symmetric::{decrypt, encrypt},
    },
    utils::{crypto_error, MatterError},
};

use super::{
    enums::{MessageType, SessionOrigin, SessionRole},
    matter_message::message::MatterMessage,
    message_reception::MessageReceptionState,
};

pub mod enums;
pub mod interaction_model;
pub mod secure_channel;
mod setup;

///
/// @author Mihael Berčič
/// @date 18. 9. 24
///
#[derive(Clone, Debug)]
pub struct Session {
    pub session_origin: SessionOrigin,
    pub session_role: SessionRole,
    pub session_id: u16,
    pub peer_session_id: u16,
    pub prover_key: [u8; CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES],
    pub verifier_key: [u8; CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES],
    pub attestation_challenge: [u8; CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES],
    pub timestamp: u64,
    pub message_counter: u32,
    pub message_reception_state: MessageReceptionState,
    pub fabric_index: u64,
    pub peer_node_id: MatterDestinationID,
    pub local_node_id: u64,
    pub resumption_id: [u8; 16],
    pub active_timestamp: u128,
    pub session_idle_interval: u16,
    pub session_active_interval: u16,
    pub session_active_threshold: u16,
    pub peer_active_mode: bool, // < => (now() - activetimestamp) < session_active_threshold,
    pub session_setup: Option<SessionSetup>,
    pub shared_secret: Option<[u8; 32]>,
    pub case_setup: Option<CaseSessionSetup>,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            session_origin: SessionOrigin::Pase,
            session_role: SessionRole::Prover,
            session_id: 0,
            peer_session_id: 0,
            prover_key: Default::default(),
            verifier_key: Default::default(),
            attestation_challenge: Default::default(),
            timestamp: 0,
            message_counter: 0,
            message_reception_state: MessageReceptionState {
                peer_node_id: 0,
                message_type: MessageType::Acknowledgment,
                max_counter: 0,
                bitmap: 0,
            },
            fabric_index: 0,
            peer_node_id: MatterDestinationID::Node(0),
            local_node_id: 0,
            resumption_id: [0; 16],
            active_timestamp: 0,
            session_idle_interval: 500,
            session_active_interval: 600,
            session_active_threshold: 4000,
            peer_active_mode: false,
            session_setup: Some(Default::default()),
            shared_secret: None,
            case_setup: None,
        }
    }
}
impl Session {
    /// Decode matter message by using cryptography keys of the session.
    pub fn decode(&self, matter_message: &mut MatterMessage) -> Result<(), MatterError> {
        if matter_message.header.is_insecure_unicast_session() {
            return Ok(());
        }
        let encrypted = &matter_message.payload;
        let header = &matter_message.header;
        let mut nonce = vec![];
        let mut source_node_id = header.source_node_id.unwrap_or(UNSPECIFIED_NODE_ID);

        if let MatterDestinationID::Node(id) = self.peer_node_id {
            if self.session_id == 6969 {
                source_node_id = id;
                //log_info!("Setting the source node id to {}", id);
            }
        }

        nonce.push(header.security_flags.flags);
        nonce.write_u32::<LE>(header.message_counter)?;
        nonce.write_u64::<LE>(source_node_id)?;

        let additional: Vec<u8> = header.clone().into();
        let payload = Payload { msg: encrypted, aad: &additional };
        let decrypted = decrypt(&self.prover_key, payload, &nonce.try_into()?);
        let Ok(decrypted) = decrypted else {
            return Err(crypto_error("Unable to decrypt the message."));
        };
        matter_message.payload = decrypted;
        Ok(())
    }

    pub fn encode(&self, matter_message: &mut MatterMessage) -> Result<(), MatterError> {
        if matter_message.header.is_insecure_unicast_session() {
            return Ok(());
        }
        let encrypted = &matter_message.payload;
        let header = &matter_message.header;
        let mut nonce = vec![];
        let mut source_node_id = header.source_node_id.unwrap_or(UNSPECIFIED_NODE_ID);

        if self.session_id == 6969 {
            source_node_id = self.local_node_id;
            //log_info!("Setting the source node id to {}", source_node_id);
        }

        nonce.push(header.security_flags.flags);
        nonce.write_u32::<LE>(header.message_counter)?;
        nonce.write_u64::<LE>(source_node_id)?;

        let additional: Vec<u8> = header.clone().into();
        let payload = Payload { msg: encrypted, aad: &additional };
        let encrypted = encrypt(&self.verifier_key, payload, &nonce.try_into()?);
        let Ok(encrypted) = encrypted else {
            return Err(crypto_error("Unable to encrypt the message."));
        };
        matter_message.payload = encrypted;
        Ok(())
    }
}
