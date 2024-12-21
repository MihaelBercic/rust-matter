use std::any::Any;

use crate::rewrite::device::Device;

use super::information_blocks::{
    attribute::{AttributePath, AttributeReport},
    command::{CommandData, InvokeResponse},
};

pub trait ClusterImplementation: Any {
    /// Read attributes of a cluster based on the [AttributePath] provided.
    ///
    /// Returns a vector of attribute reports for each specific attribute read.
    fn read_attribute(&self, path: &AttributePath) -> Vec<AttributeReport>;

    /// Invoke a command based on the [CommandData].
    ///
    /// Return a vector of InvokeResponses, (usually command invocations).
    #[allow(unused_variables)]
    fn invoke_command(&self, device: &mut Device, data: CommandData) -> Vec<InvokeResponse> {
        todo!("Not yet implemented.")
    }

    /// Used for Box<dyn ClusterImplementation> storage and abstraction of clusters.
    ///
    /// Needed for device endpoint storage and easier manueverability.
    fn as_any(&mut self) -> &mut dyn Any;
}
