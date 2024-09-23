use crate::session::protocol::interaction::device::ClusterImplementation;
use std::collections::HashMap;

///
/// @author Mihael Berčič
/// @date 23. 9. 24
///
pub struct Endpoint {
    cluster_map: HashMap<ClusterID, Box<dyn ClusterImplementation>>,
}

pub struct EndpointBuilder {
    endpoint: Endpoint,
}

impl EndpointBuilder {
    pub fn new() -> EndpointBuilder {
        Self {
            endpoint: Endpoint { cluster_map: HashMap::new() },
        }
    }

    pub fn add_cluster<T: ClusterImplementation + 'static>(mut self, cluster: ClusterID, implementation: T) -> Self {
        self.endpoint.cluster_map.insert(cluster, Box::new(implementation));
        self
    }

    pub fn build(self) -> Endpoint {
        self.endpoint
    }
}


#[derive(Eq, Hash, PartialEq)]
pub enum ClusterID {
    BasicInformation = 0x0028,
    OnOffCluster = 0x0006,
}
