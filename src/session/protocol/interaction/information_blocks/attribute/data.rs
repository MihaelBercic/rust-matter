use crate::session::protocol::interaction::information_blocks::AttributePath;
use crate::tlv::element_type::ElementType;
use crate::tlv::element_type::ElementType::Structure;
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::Tlv;

///
/// @author Mihael Berčič
/// @date 27. 9. 24
///
#[derive(Debug)]
pub struct AttributeData {
    pub data_version: u32,
    pub path: AttributePath,
    pub data: Tlv,
}

impl From<AttributeData> for ElementType {
    fn from(value: AttributeData) -> Self {
        Structure(vec![
            Tlv::new(value.data_version.into(), ContextSpecific8, Tag::short(0)),
            Tlv::new(value.path.into(), ContextSpecific8, Tag::short(1)),
            value.data,
        ])
    }
}
