use crate::session::protocol::interaction::information_blocks::AttributePath;
use crate::tlv::tlv::TLV;

///
/// @author Mihael Berčič
/// @date 24. 9. 24
///
pub struct AttributeReport {
    pub status: AttributeStatus,
    pub data: AttributeData,
}

pub struct AttributeStatus {
    pub path: AttributePath,
    pub status: Status,
}

pub struct AttributeData {
    pub data_version: u32,
    pub path: AttributePath,
    pub data: TLV,
}

pub struct Status {
    pub status: u8,
    pub cluster_status: u8,
}