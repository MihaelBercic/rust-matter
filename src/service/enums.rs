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
    Unpaired,
    Pairing,
    Paired,
}