use crate::{rewrite::protocol_message::ProtocolMessageBuilder, tlv::structs::StatusReport, utils::MatterError};

pub mod cluster_implementation;
pub mod clusters;
pub mod enums;
pub mod information_blocks;

pub(crate) fn process_interaction() -> Result<Vec<ProtocolMessageBuilder>, MatterError> {
    todo!("Not yet implemented")
}
