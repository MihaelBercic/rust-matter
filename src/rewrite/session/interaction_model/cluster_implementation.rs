use std::any::Any;

use crate::{
    rewrite::session::interaction_model::attribute::{AttributePath, AttributeReport},
    tlv::structs::StatusReport,
};

pub trait ClusterImplementation: Any {
    fn read_attribute(&self, path: &AttributePath) -> Vec<AttributeReport>;
    fn as_any(&mut self) -> &mut dyn Any;
}
