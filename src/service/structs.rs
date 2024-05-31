pub struct MatterMessage {
    pub header: MatterMessageHeader,
    pub payload: Vec<u8>,
    pub integrity_check: Vec<u8>,
}

#[derive(Debug)]
pub struct MatterMessageHeader {
    pub payload_length: u16,
    pub flags: MatterMessageFlags,
    pub session_id: u16,
    pub security_flags: MatterSecurityFlags,
    pub message_counter: u32,
    pub source_node_id: Option<[u8; 8]>,
    pub destination_node_id: Option<MatterDestinationID>,
    pub message_extensions: Option<MatterMessageExtension>,
}

#[derive(Debug)]
pub struct MatterMessageFlags {
    pub(crate) flags: u8,
}

#[derive(Debug)]
pub struct MatterSecurityFlags {
    pub(crate) flags: u8,
}

#[derive(Debug)]
pub struct MatterMessageExtension {
    pub data: Vec<u8>,
}

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