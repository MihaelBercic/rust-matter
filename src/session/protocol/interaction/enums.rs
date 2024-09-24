use crate::utils::MatterError;

///
/// @author Mihael Berčič
/// @date 24. 9. 24
///
#[derive(Clone, Debug)]
pub enum QueryParameter<T> {
    Wildcard,
    Specific(T),
}

#[derive(Eq, Hash, PartialEq, Clone, Copy)]
#[repr(u32)]
pub enum ClusterID {
    BasicInformation = 0x0028,
    OnOffCluster = 0x0006,
}

#[repr(u8)]
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum InteractionProtocolOpcode {
    StatusResponse = 0x01,
    ReadRequest = 0x02,
    SubscribeRequest = 0x03,
    SubscribeResponse = 0x04,
    ReportData = 0x05,
    WriteRequest = 0x06,
    WriteResponse = 0x07,
    InvokeRequest = 0x08,
    InvokeResponse = 0x09,
    TimedRequest = 0x0A,
}

impl From<u8> for InteractionProtocolOpcode {
    fn from(value: u8) -> Self {
        match value {
            0x01 => InteractionProtocolOpcode::StatusResponse,
            0x02 => InteractionProtocolOpcode::ReadRequest,
            0x03 => InteractionProtocolOpcode::SubscribeRequest,
            0x04 => InteractionProtocolOpcode::SubscribeResponse,
            0x05 => InteractionProtocolOpcode::ReportData,
            0x06 => InteractionProtocolOpcode::WriteRequest,
            0x07 => InteractionProtocolOpcode::WriteResponse,
            0x08 => InteractionProtocolOpcode::InvokeRequest,
            0x09 => InteractionProtocolOpcode::InvokeResponse,
            0x0A => InteractionProtocolOpcode::TimedRequest,
            _ => panic!("Unknown Interaction Opcode"),
        }
    }
}

impl TryFrom<u32> for ClusterID {
    type Error = MatterError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x0006 => Ok(ClusterID::OnOffCluster),
            _ => Ok(ClusterID::BasicInformation),
        }
    }
}
