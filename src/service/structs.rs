pub struct MatterMessage {
    pub header: MatterMessageHeader,
    pub payload: Vec<u8>,
    pub integrity_check: Vec<u8>,
}

#[derive(Debug)]
pub struct MatterMessageHeader {
    pub(crate) payload_length: u16,
    pub(crate) flags: MatterMessageFlags,
    pub(crate) session_id: u16,
    pub(crate) security_flags: MatterSecurityFlags,
    pub(crate) message_counter: u32,
    pub(crate) source_node_id: Option<[u8; 8]>,
    pub(crate) destination_node_id: Option<MatterDestinationID>,
    pub(crate) message_extensions: Option<MatterMessageExtension>,
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
    pub(crate) data: Vec<u8>,
}

#[derive(PartialEq)]
pub enum MatterSessionType {
    Unicast,
    Group,
    ReservedForFuture,
}

#[derive(Debug)]
pub enum MatterDestinationID {
    Short(u16),
    Long(u64),
    ShortGroupID,
    LongGroupID,
}