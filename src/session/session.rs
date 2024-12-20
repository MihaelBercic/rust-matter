use crate::constants::UNSPECIFIED_NODE_ID;
use crate::crypto::constants::{CONTEXT_PREFIX_VALUE, CRYPTO_PBKDF_ITERATIONS_MIN, CRYPTO_PUBLIC_KEY_SIZE_BYTES, CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES};
use crate::crypto::spake::spake_confirmation::SpakeConfirmation;
use crate::crypto::symmetric::{decrypt, encrypt};
use crate::session::matter::enums::{MatterDestinationID, MessageType, SessionOrigin};
use crate::session::matter_message::MatterMessage;
use crate::session::message_reception::MessageReceptionState;
use crate::session::SessionRole;
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
    pub local_node_id: u64,
    pub resumption_id: u32,
    pub active_timestamp: u128,
    pub session_idle_interval: u16,
    pub session_active_interval: u16,
    pub session_active_threshold: u16,
    pub peer_active_mode: bool, // < => (now() - activetimestamp) < session_active_threshold,
    pub session_setup: Option<SessionSetup>,
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
            resumption_id: 0,
            active_timestamp: 0,
            session_idle_interval: 500,
            session_active_interval: 600,
            session_active_threshold: 4000,
            peer_active_mode: false,
            session_setup: Some(Default::default()),
        }
    }
}
impl Session {
    pub fn decode(&self, matter_message: &mut MatterMessage) -> Result<(), MatterError> {
        if matter_message.header.is_insecure_unicast_session() {
            return Ok(());
        }
        let encrypted = &matter_message.payload;
        let header = &matter_message.header;
        let mut nonce = vec![];
        let source_node_id = header.source_node_id.unwrap_or(UNSPECIFIED_NODE_ID);
        nonce.push(header.security_flags.flags);
        nonce.write_u32::<LE>(header.message_counter)?;
        nonce.write_u64::<LE>(source_node_id)?;

        let additional = &header.to_bytes();
        let payload = Payload {
            msg: encrypted,
            aad: &header.to_bytes(),
        };
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
        let source_node_id = header.source_node_id.unwrap_or(UNSPECIFIED_NODE_ID);
        nonce.push(header.security_flags.flags);
        nonce.write_u32::<LE>(header.message_counter)?;
        nonce.write_u64::<LE>(source_node_id)?;

        let additional = &header.to_bytes();
        let payload = Payload {
            msg: encrypted,
            aad: &header.to_bytes(),
        };
        let encrypted = encrypt(&self.verifier_key, payload, &nonce.try_into()?);
        let Ok(encrypted) = encrypted else {
            return Err(crypto_error("Unable to encrypt the message."));
        };
        matter_message.payload = encrypted;
        Ok(())
    }
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

#[derive(Debug, Clone)]
pub struct SessionSetup {
    pub peer_session_id: u16,
    pub session_id: u16,
    pub iterations: u32,
    pub salt: [u8; 32],
    pub p_a: Option<[u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES]>,
    pub p_b: Option<[u8; CRYPTO_PUBLIC_KEY_SIZE_BYTES]>,
    pub confirmation: Option<SpakeConfirmation>,
    pub context: Vec<u8>,
}

impl SessionSetup {
    pub fn add_to_context(&mut self, data: &[u8]) {
        self.context.extend_from_slice(data);
    }
}

impl Default for SessionSetup {
    fn default() -> Self {
        Self {
            session_id: 0,
            salt: Default::default(),
            p_a: None,
            p_b: None,
            iterations: CRYPTO_PBKDF_ITERATIONS_MIN,
            peer_session_id: 0,
            context: CONTEXT_PREFIX_VALUE.to_vec(),
            confirmation: None,
        }
    }
}
