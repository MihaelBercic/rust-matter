use crate::tlv::element_type::ElementType;
use crate::tlv::element_type::ElementType::{Array, Structure};
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::TLV;

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
        Structure(
            vec![
                TLV::new(value.network_id.clone().into(), ContextSpecific8, Tag::simple(Short(0))),
                TLV::new(value.connected.clone().into(), ContextSpecific8, Tag::simple(Short(1))),
            ]
        )
    }
}

impl From<Vec<NetworkInfo>> for ElementType {
    fn from(value: Vec<NetworkInfo>) -> Self {
        let mut vec = vec![];
        for x in value {
            vec.push(TLV::simple(x.into()))
        }
        Array(vec)
    }
}


