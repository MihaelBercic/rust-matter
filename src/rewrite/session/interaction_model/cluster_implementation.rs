use std::any::Any;

use super::information_blocks::attribute::{AttributePath, AttributeReport};

pub trait ClusterImplementation: Any {
    /// Read attributes of a cluster based on the [AttributePath] provided.
    ///
    /// Returns a vector of attribute reports for each specific attribute read.
    fn read_attribute(&self, path: &AttributePath) -> Vec<AttributeReport>;

    /// Used for Box<dyn ClusterImplementation> storage and abstraction of clusters.
    ///
    /// Needed for device endpoint storage and easier manueverability.
    fn as_any(&mut self) -> &mut dyn Any;
}
