use crate::service::protocol::structs::ProtocolMessage;

pub trait MRP {
    fn check_validity(&self, message: ProtocolMessage);
    fn obtain_keys(&self);
}

pub trait PrivacyProcessing {
    fn process_privacy(&self);
}