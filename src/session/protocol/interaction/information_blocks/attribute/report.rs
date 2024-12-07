use crate::session::protocol::interaction::enums::QueryParameter::Specific;
use crate::session::protocol::interaction::information_blocks::attribute::{AttributeData, AttributeStatus};
use crate::tlv::element_type::ElementType;
use crate::tlv::element_type::ElementType::Structure;
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tlv::Tlv;

///
/// @author Mihael Berčič
/// @date 27. 9. 24
///
#[derive(Debug)]
pub struct AttributeReport {
    pub status: Option<AttributeStatus>,
    pub data: Option<AttributeData>,
}

impl AttributeReport {
    pub fn set_node_id(&mut self, id: u64) {
        if let Some(status) = &mut self.status {
            status.path.node_id = Specific(id);
        }
        if let Some(data) = &mut self.data {
            data.path.node_id = Specific(id);
        }
    }

    pub fn set_endpoint_id(&mut self, id: u16) {
        if let Some(status) = &mut self.status {
            status.path.endpoint_id = Specific(id);
        }
        if let Some(data) = &mut self.data {
            data.path.endpoint_id = Specific(id);
        }
    }

    pub fn set_cluster_id(&mut self, id: u32) {
        if let Some(status) = &mut self.status {
            status.path.cluster_id = Specific(id);
        }
        if let Some(data) = &mut self.data {
            data.path.cluster_id = Specific(id);
        }
    }

    pub fn set_attribute_id(&mut self, id: u32) {
        if let Some(status) = &mut self.status {
            status.path.attribute_id = Specific(id);
        }
        if let Some(data) = &mut self.data {
            data.path.attribute_id = Specific(id);
        }
    }
}

impl From<AttributeReport> for ElementType {
    fn from(value: AttributeReport) -> Self {
        let mut vec = vec![];
        if let Some(status) = value.status {
            vec.push(Tlv::new(status.into(), ContextSpecific8, Tag::short(0)));
        }
        if let Some(data) = value.data {
            vec.push(Tlv::new(data.into(), ContextSpecific8, Tag::short(1)));
        }
        Structure(vec)
    }
}
