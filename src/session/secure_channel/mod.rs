use crate::network::network_message::NetworkMessage;
use crate::session::insecure::process_insecure;
use crate::session::matter_message::MatterMessage;
use crate::session::protocol::enums::SecureChannelProtocolOpcode;
use crate::session::protocol_message::ProtocolMessage;
use crate::tlv::structs::status_report;
use crate::utils::MatterLayer::Transport;
use crate::utils::{generic_error, MatterError};

pub(crate) mod session;

pub fn process_secure_channel(matter_message: MatterMessage, protocol_message: ProtocolMessage) -> Result<NetworkMessage, MatterError> {
    let opcode = SecureChannelProtocolOpcode::from(protocol_message.opcode);
    match opcode {
        SecureChannelProtocolOpcode::StatusReport => {
            let status_report = status_report::StatusReport::try_from(protocol_message);
            let representation = format!("{:?}", status_report);
            return Err(MatterError::Custom(Transport, representation));
        }
        SecureChannelProtocolOpcode::MRPStandaloneAcknowledgement => {
            // TODO: Remove from retransmission...
            return Err(generic_error("Nothing to do about this..."));
        }
        _ => {}
    }
    process_insecure(matter_message, protocol_message)
}