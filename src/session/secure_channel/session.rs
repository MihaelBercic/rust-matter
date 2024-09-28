use crate::crypto::constants::CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES;
use crate::crypto::symmetric::{decrypt, encrypt};
use crate::session::matter::enums::{MatterDestinationID, SessionOrigin};
use crate::session::matter_message::MatterMessage;
use crate::session::message_reception::MessageReceptionState;
use crate::session::{SessionRole, UNSPECIFIED_NODE_ID};
use crate::utils::{crypto_error, MatterError};
use byteorder::{WriteBytesExt, LE};
use ccm::aead::Payload;

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
    pub resumption_id: u32,
    pub active_timestamp: u128,
    pub session_idle_interval: u16,
    pub session_active_interval: u16,
    pub session_active_threshold: u16,
    pub peer_active_mode: bool, // < => (now() - activetimestamp) < session_active_threshold,
}

impl Session {
    pub fn decode(&self, matter_message: &MatterMessage) -> Result<Vec<u8>, MatterError> {
        let encrypted = &matter_message.payload;
        let header = &matter_message.header;
        let mut nonce = vec![];
        let source_node_id = header.source_node_id.unwrap_or(UNSPECIFIED_NODE_ID);
        nonce.push(header.security_flags.flags);
        nonce.write_u32::<LE>(header.message_counter)?;
        nonce.write_u64::<LE>(source_node_id)?;

        let additional = &header.to_bytes();
        let payload = Payload { msg: encrypted, aad: &header.to_bytes() };
        let decrypted = decrypt(&self.prover_key, payload, &nonce.try_into()?);
        let Ok(decrypted) = decrypted else {
            return Err(crypto_error("Unable to decrypt the message."))
        };
        Ok(decrypted)
    }

    pub fn encode(&self, matter_message: &mut MatterMessage) -> Result<(), MatterError> {
        let encrypted = &matter_message.payload;
        let header = &matter_message.header;
        let mut nonce = vec![];
        let source_node_id = header.source_node_id.unwrap_or(UNSPECIFIED_NODE_ID);
        nonce.push(header.security_flags.flags);
        nonce.write_u32::<LE>(header.message_counter)?;
        nonce.write_u64::<LE>(source_node_id)?;

        let additional = &header.to_bytes();
        let payload = Payload { msg: encrypted, aad: &header.to_bytes() };
        let encrypted = encrypt(&self.prover_key, payload, &nonce.try_into()?);
        let Ok(encrypted) = encrypted else {
            return Err(crypto_error("Unable to encrypt the message."))
        };
        matter_message.payload = encrypted;
        Ok(())
    }

    // TODO: pub fn encode(&self, matter_message: &MatterMessage) -> &MatterMessage {}
}

/*
Option<SharedSecret>
LocalMessageCounter
MessageReceptionState
Local Fabric Index = 0 for PASE
PeerNodeID
ResumptionID
ActiveTimestamp

a. SESSION_IDLE_INTERVAL            | SESSION_PARAM_SET
b. SESSION_ACTIVE_INTERVAL          | SESSION_PARAM_SET
c. SESSION_ACTIVE_THRESHOLD         | SESSION_PARAM_SET
PeerActiveMode = bool <=> (now() - ActiveTimestamp) < SESSION_ACTIVE_THRESHOLD
 */
