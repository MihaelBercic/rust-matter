use crate::tlv::element_type::ElementType;
use crate::tlv::element_type::ElementType::{Array, Structure};
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::Tlv;

///
/// @author Mihael Berčič
/// @date 8. 10. 24
///
#[derive(Clone)]
pub struct NetworkInfo {
    pub network_id: Vec<u8>,
    pub connected: bool,
}

impl From<NetworkInfo> for ElementType {
    fn from(value: NetworkInfo) -> Self {
        Structure(vec![
            Tlv::new(value.network_id.clone().into(), ContextSpecific8, Tag::short(0)),
            Tlv::new(value.connected.clone().into(), ContextSpecific8, Tag::short(1)),
        ])
    }
}

impl From<Vec<NetworkInfo>> for ElementType {
    fn from(value: Vec<NetworkInfo>) -> Self {
        let mut vec = vec![];
        for x in value {
            vec.push(Tlv::simple(x.into()))
        }
        Array(vec)
    }
}
