use crate::session::protocol::interaction::cluster::ClusterImplementation;
use crate::session::protocol::interaction::endpoint::Endpoint;
use crate::session::protocol::interaction::enums::ClusterID;
use std::collections::HashMap;

///
/// @author Mihael Berčič
/// @date 24. 9. 24
///
pub struct EndpointBuilder {
    endpoint: Endpoint,
}

impl EndpointBuilder {
    pub fn new() -> EndpointBuilder {
        Self {
            endpoint: Endpoint { clusters: HashMap::new() },
        }
    }

    pub fn add_cluster<T: ClusterImplementation + 'static>(mut self, cluster: ClusterID, implementation: T) -> Self {
        self.endpoint.clusters.insert(cluster, Box::new(implementation));
        self
    }

    pub fn build(self) -> Endpoint {
        self.endpoint
    }
}

