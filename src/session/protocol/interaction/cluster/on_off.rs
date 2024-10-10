use crate::session::protocol::interaction::cluster::ClusterImplementation;
use crate::session::protocol::interaction::information_blocks::attribute::report::AttributeReport;
use crate::session::protocol::interaction::information_blocks::attribute::Attribute;
use crate::session::protocol::interaction::information_blocks::{AttributePath, CommandData, InvokeResponse};
use std::any::Any;

///
/// @author Mihael Berčič
/// @date 10. 10. 24
///
pub struct OnOffCluster {
    is_on: Attribute<bool>,
}

impl OnOffCluster {
    pub fn new() -> Self {
        Self {
            is_on: Attribute {
                id: 0,
                value: false,
            },
        }
    }
}

impl ClusterImplementation for OnOffCluster {
    fn read_attributes(&self, attribute_path: AttributePath) -> Vec<AttributeReport> {
        vec![self.is_on.clone().into()]
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    fn invoke_command(&mut self, command: CommandData) -> Vec<InvokeResponse> {
        todo!("Invoking OnOff command!")
    }
}