use crate::tlv::element_type::ElementType;
use crate::tlv::element_type::ElementType::Structure;
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::Tlv;

///
/// @author Mihael Berčič
/// @date 8. 10. 24
///
#[derive(Clone)]
pub struct CapabilityMinima {
    case_sessions_per_fabric: u16, // min = 3
    subscriptions_per_fabric: u16, // min = 3
}

impl From<CapabilityMinima> for ElementType {
    fn from(value: CapabilityMinima) -> Self {
        Structure(vec![
            Tlv::new(value.case_sessions_per_fabric.into(), TagControl::ContextSpecific8, Tag::short(0)),
            Tlv::new(value.subscriptions_per_fabric.into(), TagControl::ContextSpecific8, Tag::short(1)),
        ])
    }
}

impl Default for CapabilityMinima {
    fn default() -> Self {
        Self {
            case_sessions_per_fabric: 3,
            subscriptions_per_fabric: 3,
        }
    }
}

impl CapabilityMinima {
    pub fn as_element_type(&self) -> ElementType {
        Structure(vec![
            Tlv::new(self.case_sessions_per_fabric.into(), TagControl::ContextSpecific8, Tag::short(0)),
            Tlv::new(self.subscriptions_per_fabric.into(), TagControl::ContextSpecific8, Tag::short(1)),
        ])
    }
}
