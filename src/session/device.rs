use std::{collections::HashMap, mem::take};

use crate::{
    log_debug,
    mdns::device_information::Details,
    session::protocol::interaction::{
        enums::{GlobalStatusCode, QueryParameter},
        information_blocks::{
            attribute::status::{AttributeStatus, Status},
            CommandStatus,
        },
    },
};

use super::{
    protocol::interaction::{
        cluster::ClusterImplementation,
        enums::ClusterID,
        information_blocks::{attribute::report::AttributeReport, AttributePath, CommandData, InvokeResponse},
    },
    session::Session,
};

pub struct Device {
    pub endpoints_map: HashMap<u16, HashMap<u32, Box<dyn ClusterImplementation + Send>>>,
    pub details: Details,
}

impl Device {
    pub fn new(device_information: Details) -> Self {
        Self {
            endpoints_map: Default::default(),
            details: device_information,
        }
    }

    pub fn insert(&mut self, endpoint_id: u16, cluster_id: ClusterID, cluster: impl ClusterImplementation + std::marker::Send) {
        let mut endpoint_map = self.endpoints_map.entry(endpoint_id).or_insert_with(HashMap::new);
        endpoint_map.insert(cluster_id as u32, Box::new(cluster));
    }

    fn get<T: ClusterImplementation>(&mut self, endpoint_id: u16, cluster_id: ClusterID) -> Option<&mut T> {
        self.endpoints_map
            .get_mut(&endpoint_id)
            .map(|cluster_map| cluster_map.get_mut(&(cluster_id as u32)).map(|cluster| cluster.as_any().downcast_mut())?)?
    }

    pub(crate) fn read_attributes(&mut self, attribute_path: AttributePath) -> Vec<AttributeReport> {
        let cluster_information = if let QueryParameter::Specific(id) = attribute_path.cluster_id {
            format!("{:?}", ClusterID::from(id))
        } else {
            format!("{:?}", attribute_path.cluster_id)
        };
        // log_debug!(
        //     "[READ] Endpoint: {:?}, Cluster: {:?}, Attribute: {:?}",
        //     attribute_path.endpoint_id,
        //     cluster_information,
        //     attribute_path.attribute_id
        // );
        match attribute_path.endpoint_id {
            QueryParameter::Wildcard => {
                let mut vec = vec![];
                for (endpoint_id, cluster_map) in &mut self.endpoints_map {
                    if let QueryParameter::Specific(cluster_id) = attribute_path.cluster_id {
                        if cluster_map.contains_key(&cluster_id) {
                            let mut reports = Self::read_cluster(cluster_map, *endpoint_id, attribute_path.clone());
                            for ar in &mut reports {
                                ar.set_endpoint_id(*endpoint_id);
                            }
                            vec.extend(reports);
                        }
                    }
                }
                vec
            }
            QueryParameter::Specific(endpoint_id) => {
                let mut cluster_map = self.endpoints_map.get_mut(&endpoint_id);
                let mut vec = vec![];
                if let Some(cluster_map) = cluster_map {
                    let mut reports = Self::read_cluster(cluster_map, endpoint_id, attribute_path);
                    for ar in &mut reports {
                        ar.set_endpoint_id(endpoint_id);
                    }
                    vec.extend(reports)
                } else {
                    vec.push(AttributeReport {
                        status: Some(AttributeStatus {
                            path: attribute_path,
                            status: Status {
                                status: GlobalStatusCode::UnsupportedEndpoint as u8,
                                cluster_status: 0,
                            },
                        }),
                        data: None,
                    })
                }
                vec
            }
        }
    }

    pub(crate) fn invoke_command(&mut self, command: CommandData, session: &mut Session) -> Vec<InvokeResponse> {
        let command_path = command.path.clone();
        let cluster_information = if let QueryParameter::Specific(id) = command_path.cluster_id {
            format!("{:?}", ClusterID::from(id))
        } else {
            format!("{:?}", command_path.cluster_id)
        };
        // log_debug!(
        //     "[INVOKE] Endpoint: {:?}, Cluster: {:?}, Command: {:?}",
        //     command_path.endpoint_id,
        //     cluster_information,
        //     command_path.command_id
        // );

        match command_path.endpoint_id {
            QueryParameter::Wildcard => {
                let mut vec = vec![];

                for (endpoint_id, cluster_map) in &mut self.endpoints_map {
                    vec.extend(Self::invoke_cluster(
                        cluster_map,
                        *endpoint_id,
                        command.clone(),
                        session,
                        &mut self.details,
                    ))
                }
                vec
            }
            QueryParameter::Specific(endpoint_id) => {
                let mut cluster_map = self.endpoints_map.get_mut(&endpoint_id);
                let mut vec = vec![];
                if let Some(cluster_map) = cluster_map {
                    vec.extend(Self::invoke_cluster(cluster_map, endpoint_id, command, session, &mut self.details))
                } else {
                    vec.push(InvokeResponse {
                        status: Some(CommandStatus {
                            path: command_path,
                            status: Status {
                                status: GlobalStatusCode::UnsupportedEndpoint as u8,
                                cluster_status: 0,
                            },
                        }),
                        command: None,
                    })
                }
                vec
            }
        }
    }

    fn read_cluster(
        cluster_map: &mut HashMap<u32, Box<dyn ClusterImplementation + Send>>,
        endpoint_id: u16,
        attribute_path: AttributePath,
    ) -> Vec<AttributeReport> {
        let mut vec = vec![];
        match attribute_path.cluster_id {
            QueryParameter::Wildcard => {
                for (cluster_id, cluster) in cluster_map {
                    let mut to_add = cluster.read_attributes(attribute_path.clone());
                    for a_r in &mut to_add {
                        a_r.set_cluster_id(*cluster_id);
                    }
                    vec.extend(to_add);
                }
            }
            QueryParameter::Specific(cluster_id) => {
                if let Some(cluster) = cluster_map.get_mut(&cluster_id) {
                    let mut to_add = cluster.read_attributes(attribute_path.clone());
                    for a_r in &mut to_add {
                        a_r.set_cluster_id(cluster_id);
                    }
                    vec.extend(to_add);
                } else {
                    vec.push(AttributeReport {
                        status: Some(AttributeStatus {
                            path: attribute_path,
                            status: Status {
                                status: GlobalStatusCode::UnsupportedCluster as u8,
                                cluster_status: 0,
                            },
                        }),
                        data: None,
                    })
                }
            }
        }

        vec
    }

    fn invoke_cluster(
        cluster_map: &mut HashMap<u32, Box<dyn ClusterImplementation + Send>>,
        endpoint_id: u16,
        command: CommandData,
        session: &mut Session,
        information: &mut Details,
    ) -> Vec<InvokeResponse> {
        let mut vec = vec![];
        let command_path = command.path.clone();
        match command_path.cluster_id {
            QueryParameter::Wildcard => {
                for (cluster_id, cluster) in cluster_map {
                    let mut to_add = cluster.invoke_command(command.clone(), session, information);
                    for a_r in &mut to_add {
                        a_r.set_cluster_id(*cluster_id);
                        a_r.set_endpoint_id(endpoint_id);
                    }
                    vec.extend(to_add);
                }
            }
            QueryParameter::Specific(cluster_id) => {
                if let Some(cluster) = cluster_map.get_mut(&cluster_id) {
                    let mut to_add = cluster.invoke_command(command.clone(), session, information);
                    for a_r in &mut to_add {
                        a_r.set_cluster_id(cluster_id);
                        a_r.set_endpoint_id(endpoint_id);
                    }
                    vec.extend(to_add);
                } else {
                    vec.push(InvokeResponse {
                        status: Some(CommandStatus {
                            path: command_path,
                            status: Status {
                                status: GlobalStatusCode::UnsupportedCluster as u8,
                                cluster_status: 0,
                            },
                        }),
                        command: None,
                    })
                }
            }
        }

        vec
    }

    pub fn modify_cluster<'a, T: ClusterImplementation>(&mut self, endpoint_id: u16, cluster_id: ClusterID, c: fn(&mut T)) {
        if let Some(cluster) = self.get::<T>(endpoint_id, cluster_id) {
            c(cluster);
        }
    }
}
