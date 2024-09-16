use crate::secure::protocol::enums::ProtocolCode::{Busy, CloseSession, InvalidParameter, NoSharedTrustRoots, SessionEstablishmentSuccess};
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

#[derive(Debug)]
#[repr(u16)]
pub enum GeneralCode {
    Success = 0,
    Failure = 1,
    BadPrecondition = 2,
    OutOfRange = 3,
    BadRequest = 4,
    Unsupported = 5,
    Unexpected = 6,
    ResourceExhausted = 7,
    Busy = 8,
    Timeout = 9,
    Continue = 10,
    Aborted = 11,
    InvalidArgument = 12,
    NotFound = 13,
    AlreadyExists = 14,
    PermissionDenied = 15,
    DataLoss = 16,
}

impl<T> From<T> for GeneralCode
    where T: Into<u16>
{
    fn from(value: T) -> Self {
        let u16 = value.into();
        match u16 {
            0 => GeneralCode::Success,
            1 => GeneralCode::Failure,
            2 => GeneralCode::BadPrecondition,
            3 => GeneralCode::OutOfRange,
            4 => GeneralCode::BadRequest,
            5 => GeneralCode::Unsupported,
            6 => GeneralCode::Unexpected,
            7 => GeneralCode::ResourceExhausted,
            8 => GeneralCode::Busy,
            9 => GeneralCode::Timeout,
            10 => GeneralCode::Continue,
            11 => GeneralCode::Aborted,
            12 => GeneralCode::InvalidArgument,
            13 => GeneralCode::NotFound,
            14 => GeneralCode::AlreadyExists,
            15 => GeneralCode::PermissionDenied,
            _ => GeneralCode::DataLoss,
        }
    }
}


#[derive(Debug)]
#[repr(u16)]
pub enum ProtocolCode {
    SessionEstablishmentSuccess = 0x0000,
    NoSharedTrustRoots = 0x0001,
    InvalidParameter = 0x0002,
    CloseSession = 0x0003,
    Busy = 0x0004,
}

impl From<u16> for ProtocolCode {
    fn from(value: u16) -> Self {
        match value {
            0x0000 => SessionEstablishmentSuccess,
            0x0001 => NoSharedTrustRoots,
            0x0002 => InvalidParameter,
            0x0003 => CloseSession,
            _ => Busy
        }
    }
}
