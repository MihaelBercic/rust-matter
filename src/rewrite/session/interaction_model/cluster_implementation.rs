use std::any::Any;

use crate::{
    session::{
        protocol::interaction::information_blocks::{CommandData, InvokeResponse},
        Device,
    },
    SharedDevice,
};

use super::information_blocks::attribute::{AttributePath, AttributeReport};

pub trait ClusterImplementation: Any {
    /// Read attributes of a cluster based on the [AttributePath] provided.
    ///
    /// Returns a vector of attribute reports for each specific attribute read.
    fn read_attribute(&self, path: &AttributePath) -> Vec<AttributeReport>;

    fn invoke_command(&self, device: &mut Device, data: CommandData) -> Vec<InvokeResponse> {
        todo!("Not yet implemented.")
    }

    /// Used for Box<dyn ClusterImplementation> storage and abstraction of clusters.
    ///
    /// Needed for device endpoint storage and easier manueverability.
    fn as_any(&mut self) -> &mut dyn Any;
}
