use crate::{
    tlv::{element_type::ElementType, tag::Tag, tag_control::TagControl::ContextSpecific8, tlv::Tlv},
    utils::MatterError,
};

#[derive(Debug, Clone)]
pub struct FabricDescriptor {
    pub root_public_key: Vec<u8>,
    pub vendor_id: u16,
    pub fabric_id: u64,
    pub node_id: u64,
    pub label: String,
}

impl From<FabricDescriptor> for ElementType {
    fn from(value: FabricDescriptor) -> Self {
        let mut children = vec![
            Tlv::new(value.root_public_key.into(), ContextSpecific8, Tag::short(1)),
            Tlv::new(value.vendor_id.into(), ContextSpecific8, Tag::short(2)),
            Tlv::new(value.fabric_id.into(), ContextSpecific8, Tag::short(3)),
            Tlv::new(value.node_id.into(), ContextSpecific8, Tag::short(4)),
            Tlv::new(value.label.into(), ContextSpecific8, Tag::short(5)),
        ];
        ElementType::Structure(children)
    }
}

impl From<Vec<FabricDescriptor>> for ElementType {
    fn from(value: Vec<FabricDescriptor>) -> Self {
        let mut vec = vec![];
        for x in value {
            vec.push(Tlv::simple(x.into()))
        }
        ElementType::List(vec)
    }
}
