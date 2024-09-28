use crate::session::protocol::interaction::information_blocks::AttributePath;
use crate::tlv::tlv::TLV;

///
/// @author Mihael Berčič
/// @date 27. 9. 24
///
#[derive(Debug)]
pub struct AttributeData {
    pub data_version: u32,
    pub path: AttributePath,
    pub data: TLV,
}
