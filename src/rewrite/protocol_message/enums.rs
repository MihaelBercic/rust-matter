use ProtocolID::*;
use SecureChannelProtocolOpcode::*;
use SecureStatusProtocolCode::*;

/// @author Mihael Berčič
/// @date 5. 8. 24
///
#[repr(u8)]
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum SecureChannelProtocolOpcode {
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

#[derive(Debug)]
#[repr(u16)]
pub enum SecureChannelGeneralCode {
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

#[derive(Debug)]
#[repr(u16)]
pub enum SecureStatusProtocolCode {
    SessionEstablishmentSuccess = 0x0000,
    NoSharedTrustRoots = 0x0001,
    InvalidParameter = 0x0002,
    CloseSession = 0x0003,
    Busy = 0x0004,
}

#[repr(u8)]
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum ProtocolID {
    ProtocolSecureChannel = 0x0000,
    ProtocolInteractionModel = 0x0001,
    ProtocolBdx = 0x0002,
    ProtocolUserDirectedCommissioning = 0x0003,
    ProtocolForTesting = 0x0004,
}

impl<T> From<T> for ProtocolID
where
    T: Into<u32>,
{
    fn from(value: T) -> Self {
        let u32 = value.into();
        match u32 {
            0x0000 => ProtocolSecureChannel,
            0x0001 => ProtocolInteractionModel,
            0x0002 => ProtocolBdx,
            0x0003 => ProtocolUserDirectedCommissioning,
            0x0004 => ProtocolForTesting,
            _ => panic!("Invalid value for ProtocolID {}", u32),
        }
    }
}

impl From<u8> for SecureChannelProtocolOpcode {
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

impl<T: Into<u16>> From<T> for SecureChannelGeneralCode {
    fn from(value: T) -> Self {
        let u16 = value.into();
        match u16 {
            0 => SecureChannelGeneralCode::Success,
            1 => SecureChannelGeneralCode::Failure,
            2 => SecureChannelGeneralCode::BadPrecondition,
            3 => SecureChannelGeneralCode::OutOfRange,
            4 => SecureChannelGeneralCode::BadRequest,
            5 => SecureChannelGeneralCode::Unsupported,
            6 => SecureChannelGeneralCode::Unexpected,
            7 => SecureChannelGeneralCode::ResourceExhausted,
            8 => SecureChannelGeneralCode::Busy,
            9 => SecureChannelGeneralCode::Timeout,
            10 => SecureChannelGeneralCode::Continue,
            11 => SecureChannelGeneralCode::Aborted,
            12 => SecureChannelGeneralCode::InvalidArgument,
            13 => SecureChannelGeneralCode::NotFound,
            14 => SecureChannelGeneralCode::AlreadyExists,
            15 => SecureChannelGeneralCode::PermissionDenied,
            _ => SecureChannelGeneralCode::DataLoss,
        }
    }
}

impl From<u16> for SecureStatusProtocolCode {
    fn from(value: u16) -> Self {
        match value {
            0x0000 => SessionEstablishmentSuccess,
            0x0001 => NoSharedTrustRoots,
            0x0002 => InvalidParameter,
            0x0003 => CloseSession,
            _ => Busy,
        }
    }
}
