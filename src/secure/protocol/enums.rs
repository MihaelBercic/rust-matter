use crate::secure::protocol::enums::ProtocolOpcode::*;

///
/// @author Mihael Berčič
/// @date 5. 8. 24
///
#[repr(u8)]
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum ProtocolOpcode {
    MessageCounterSyncRequest = 0x00,
    MessageCounterSyncResponse = 0x01,

    MRPStandaloneAcknowledgement = 0x10,

    PBKDFParamRequest = 0x20,
    PBKDFParamResponse = 0x21,

    PASEPake1 = 0x22,
    PASEPake2 = 0x23,
    PASEPake3 = 0x24,

    CASESigma1 = 0x30,
    CASESigma2 = 0x31,
    CASESigma3 = 0x32,

    CASESigma2Resume = 0x33,
    StatusReport = 0x40,
}

impl From<u8> for ProtocolOpcode {
    fn from(value: u8) -> Self {
        match value {
            0x00 => MessageCounterSyncRequest,
            0x01 => MessageCounterSyncResponse,
            0x10 => MRPStandaloneAcknowledgement,
            0x20 => PBKDFParamRequest,
            0x21 => PBKDFParamResponse,
            0x22 => PASEPake1,
            0x23 => PASEPake2,
            0x24 => PASEPake3,
            0x30 => CASESigma1,
            0x31 => CASESigma2,
            0x32 => CASESigma3,
            0x33 => CASESigma2Resume,
            _ => StatusReport,
        }
    }
}