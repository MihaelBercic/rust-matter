///
/// @author Mihael Berčič
/// @date 8. 10. 24
///

#[repr(u8)]
#[derive(Clone)]
pub enum ProductFinish {
    Other = 0,
    Matter = 1,
    Satin = 2,
    Polished = 3,
    Rugged = 4,
    Fabric = 5,
}

#[repr(u8)]
#[derive(Clone)]
pub enum ProductColor {
    Black = 0,
    Navy = 1,
    Green = 2,
    Teal = 3,
    Maroon = 4,
    Purple = 5,
    Olive = 6,
    Gray = 7,
    Blue = 8,
    Lime = 9,
    Aqua = 10,
    Red = 11,
    Fuchsia = 12,
    Yellow = 13,
    White = 14,
    Nickel = 15,
    Chrome = 16,
    Brass = 17,
    Copper = 18,
    Silver = 19,
    Gold = 20,
}

#[derive(Clone)]
pub enum AvailableCommands {
    Toggle,
    On,
    Off,
    Fade,
}

pub enum CommandEvent {
    On,
    Off,
    Toggle { new_value: bool },
    Fade { to: u8 },
}

pub enum AttributeChanges {
    OnOffChange { new_value: bool },
}

pub enum ChangeEvent {
    Attribute { endpoint_id: u8, change: AttributeChanges },
    Command { endpoint_id: u8, change: CommandEvent },
}

pub enum CommissioningError {
    Ok = 0,
    ValueOutsideRange = 1,
    InvalidAuthentication = 2,
    NoFailSafe = 3,
    BusyWithOtherAdmin = 4,
}

#[derive(Clone)]
#[repr(u8)]
pub enum RegulatoryLocationType {
    Indoor = 0,
    Outdoor = 1,
    IndoorOutdoor = 2,
}

pub enum Features {
    Wifi = 0,
    Thread = 1,
    Ethernet = 2,
}

pub enum WiFiBand {
    WiFi2G4 = 0,
    WiFi3G5 = 1,
    WiFi5G = 2,
    WiFi6G = 3,
    WiFi60G = 4,
    WiFi1G = 5,
}

#[derive(Clone)]
pub enum NetworkCommissioningStatus {
    Success = 0,
    OutOfRange = 1,
    BoundsExceeded = 2,
    NetworkIDNotFound = 3,
    DuplicateNetworkID = 4,
    NetworkNotFound = 5,
    RegulatoryError = 6,
    AuthFailure = 7,
    UnsupportedSecurity = 8,
    OtherConnectionFailure = 9,
    IPv6Failed = 10,
    IPBindFailed = 11,
    UnknownError = 12,
}

#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CertificateChainType {
    DAC = 1,
    PAI = 2,
}

pub enum OperationalCertificateStatus {
    Ok = 0,
    InvalidPublicKey = 1,
    InvalidNodeOpId = 2,
    InvalidNOC = 3,
    MissingCsr = 4,
    TableFull = 5,
    InvalidAdminSubject = 6,
    FabricConflict = 9,
    LabelConflict = 10,
    InvalidFabricIndex = 11,
}
