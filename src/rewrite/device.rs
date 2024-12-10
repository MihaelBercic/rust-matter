use super::session::interaction_model::{cluster_implementation::ClusterImplementation, clusters::on_off::OnOffCluster, enums::ClusterID};
use crate::mdns::device_information::Details;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

pub type Cluster = dyn ClusterImplementation + Send;
pub type Endpoint = HashMap<u32, Box<Cluster>>;
pub type SharedDevice = Arc<Mutex<Device>>;

pub struct Device {
    pub endpoints_map: HashMap<u16, Endpoint>,
    pub details: Details,
}

pub struct EndpointBuilder {
    endpoint: Endpoint,
}

impl EndpointBuilder {
    pub fn new() -> Self {
        Self { endpoint: Default::default() }
    }

    pub fn add_cluster(&mut self, cluster: ClusterID) -> &mut Self {
        let id = cluster as u32;
        self.endpoint.insert(id, cluster.into());
        self
    }
}

impl From<ClusterID> for Box<Cluster> {
    fn from(value: ClusterID) -> Self {
        Box::new(match value {
            ClusterID::OnOff => OnOffCluster::default(),
            _ => todo!("Not yet implemented."),
        })
    }
}

impl Device {
    fn get<T: ClusterImplementation>(&mut self, endpoint_id: u16, cluster_id: ClusterID) -> Option<&mut T> {
        self.endpoints_map
            .get_mut(&endpoint_id)
            .map(|cluster_map| cluster_map.get_mut(&(cluster_id as u32)).map(|cluster| cluster.as_any().downcast_mut())?)?
    }
}
