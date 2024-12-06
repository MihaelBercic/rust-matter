use crate::{
    rewrite::session::interaction_model::attribute::{AttributePath, AttributeReport},
    tlv::structs::StatusReport,
};

pub trait ClusterImplementation {
    fn read_attribute(path: &AttributePath) -> Result<Vec<AttributeReport>, StatusReport>;
}
