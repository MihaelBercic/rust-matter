use std::any::Any;

use crate::{
    rewrite::session::interaction_model::{
        attribute::{self, Attribute, AttributeReport},
        cluster_implementation::ClusterImplementation,
        enums::QueryParameter::*,
    },
    tlv::structs::{self, StatusReport},
};

pub struct OnOffCluster {
    pub(crate) is_on: Attribute<1, bool>,
    pub(crate) brightness: Attribute<2, u8>,
}

impl Default for OnOffCluster {
    fn default() -> Self {
        Self {
            is_on: Attribute { value: false },
            brightness: Attribute { value: 0 },
        }
    }
}

impl ClusterImplementation for OnOffCluster {
    fn read_attribute(&self, path: &attribute::AttributePath) -> Vec<AttributeReport> {
        let mut reports: Vec<AttributeReport> = vec![];
        match path.attribute_id {
            Wildcard => {
                reports.extend([self.is_on.clone().into(), self.brightness.clone().into()]);
            }
            Specific(id) => match id {
                1 => reports.push(self.is_on.clone().into()),
                2 => reports.push(self.brightness.clone().into()),
                _ => todo!(),
            },
        }
        reports
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}
