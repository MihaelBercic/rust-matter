use std::net::SocketAddr;

use crate::rewrite::matter_message::message::MatterMessage;

///
/// @author Mihael Berčič
/// @date 28. 7. 24
///
#[derive(Debug)]
pub struct NetworkMessage {
    pub address: Option<SocketAddr>,
    pub message: MatterMessage,
    pub retry_counter: u8,
}
