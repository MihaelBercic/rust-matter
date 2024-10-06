use crate::session::protocol::interaction::information_blocks::AttributePath;
use crate::tlv::element_type::ElementType;
use crate::tlv::element_type::ElementType::Structure;
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl;
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::TLV;

///
/// @author Mihael Berčič
/// @date 27. 9. 24
///
#[derive(Debug)]
pub struct AttributeStatus {
    pub path: AttributePath,
    pub status: Status,
}

#[derive(Debug)]
pub struct Status {
    pub status: u8,
    pub cluster_status: u8,
}

impl From<AttributeStatus> for ElementType {
    fn from(value: AttributeStatus) -> Self {
        Structure(vec![
            TLV::new(value.path.into(), TagControl::ContextSpecific8, Tag::simple(Short(0))),
            TLV::new(value.status.into(), TagControl::ContextSpecific8, Tag::simple(Short(1))),
        ])
    }
}
impl From<Status> for ElementType {
    fn from(value: Status) -> Self {
        Structure(
            vec![
                TLV::new(value.status.into(), ContextSpecific8, Tag::simple(Short(0))),
                TLV::new(value.cluster_status.into(), ContextSpecific8, Tag::simple(Short(1))),
            ]
        )
    }
}