#[derive(PartialEq)]
pub enum MatterSessionType {
    Unicast,
    Group,
    ReservedForFuture,
}

#[derive(Debug, Eq, PartialEq)]
pub enum MatterDestinationID {
    Group(u16),
    Node(u64),
    GroupID,
    NodeID,
}