use crate::tlv::element_type::ElementType;
use crate::tlv::element_type::ElementType::Structure;
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::TLV;

///
/// @author Mihael Berčič
/// @date 8. 10. 24
///
#[derive(Clone)]
pub struct BasicCommissioningInfo {
    pub fail_safe_expiry_length_seconds: u16,
    pub max_cumulative_failsafe_seconds: u16,
}

impl From<BasicCommissioningInfo> for ElementType {
    fn from(value: BasicCommissioningInfo) -> Self {
        Structure(
            vec![
                TLV::new(value.fail_safe_expiry_length_seconds.into(), ContextSpecific8, Tag::simple(Short(0))),
                TLV::new(value.max_cumulative_failsafe_seconds.into(), ContextSpecific8, Tag::simple(Short(1))),
            ]
        )
    }
}