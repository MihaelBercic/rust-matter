use std::collections::HashMap;

use crate::service::protocol::communication::message_reception::MessageReceptionState;
use crate::transport::Transport;

mod tests;
pub mod crypto;
pub mod discovery;
pub mod useful;
pub mod service;
pub mod transport;
pub mod mrp;

pub struct Matter {
    pub reception_states: HashMap<u64, MessageReceptionState>,
    pub group_data_reception_states: HashMap<u64, MessageReceptionState>,
    pub group_control_reception_states: HashMap<u64, MessageReceptionState>,
}

impl Matter {
    pub fn start(&self) {}
    pub fn new() -> Self {
        Self {
            reception_states: Default::default(),
            group_data_reception_states: Default::default(),
            group_control_reception_states: Default::default(),
        }
    }
}