#[derive(Debug, PartialEq)]
pub enum SessionType {
    Unicast,
    Group,
    ReservedForFuture,
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum DestinationID {
    Group(u16),
    Node(u64),
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum DestinationType {
    GroupID,
    NodeID,
}

pub enum CommissioningState {
    Uncommissioned,
    Commissioning,
    Commissioned,
    Operational,
}

#[derive(Debug, Clone)]
pub enum MessageType {
    Command,
    Response,
    Event,
    Acknowledgment,
    Unknown,
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum SessionState {
    Insecure,
    Secure,
}

#[derive(Clone, Debug)]
pub enum SessionOrigin {
    Case,
    Pase,
}
