use crate::session::protocol::interaction::enums::QueryParameter::Specific;
use crate::session::protocol::interaction::information_blocks::attribute::{AttributeData, AttributeStatus};

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
}