use crate::{
    rewrite::session::interaction_model::{
        attribute::{self, Attribute, AttributeReport},
        cluster_implementation::ClusterImplementation,
    },
    tlv::structs::{self, StatusReport},
};

pub struct OnOffCluster {
    is_on: Attribute<1, bool>,
}

impl ClusterImplementation for OnOffCluster {
    fn read_attribute(path: &attribute::AttributePath) -> Result<Vec<AttributeReport>, StatusReport> {
        todo!()
    }
}
