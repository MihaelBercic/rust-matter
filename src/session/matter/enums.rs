#[derive(Debug, PartialEq)]
pub enum MatterSessionType {
    Unicast,
    Group,
    ReservedForFuture,
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum MatterDestinationID {
    Group(u16),
    Node(u64),
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum MatterDestinationType {
    GroupID,
    NodeID,
}

pub enum MatterDeviceState {
    Uncommissioned,
    Commissioning,
    Commissioned,
    Operational,
}

#[derive(Debug)]
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