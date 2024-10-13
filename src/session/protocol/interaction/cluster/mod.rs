pub mod general_commissioning;
pub mod network_commissioning;
pub mod enums;
pub mod network_info;
pub mod basic_information;
pub mod capability_minima;
pub mod basic_commissioning_info;
pub mod operational_credentials;
pub mod descriptor_cluster;
pub mod on_off;
mod icd_management;

use crate::log_debug;
use crate::session::protocol::interaction::cluster::basic_commissioning_info::BasicCommissioningInfo;
use crate::session::protocol::interaction::cluster::enums::{NetworkCommissioningStatus, ProductColor, ProductFinish, RegulatoryLocationType};
use crate::session::protocol::interaction::enums::GlobalStatusCode::{UnsupportedCluster, UnsupportedEndpoint};
use crate::session::protocol::interaction::enums::QueryParameter::Specific;
use crate::session::protocol::interaction::enums::{ClusterID, QueryParameter};
use crate::session::protocol::interaction::information_blocks::attribute::report::AttributeReport;
use crate::session::protocol::interaction::information_blocks::attribute::status::{AttributeStatus, Status};
use crate::session::protocol::interaction::information_blocks::{AttributePath, CommandData, CommandStatus, InvokeResponse};
use crate::tlv::element_type::ElementType;
use crate::tlv::element_type::ElementType::Unsigned8;
use crate::utils::{generic_error, MatterError};
use std::any::Any;
use std::collections::HashMap;

pub enum BasicInformationAttributes {
    DataModelRevision = 0x0000,
    VendorName = 0x0001,
    VendorID = 0x0002,
    ProductName = 0x0003,
    ProductID = 0x0004,
    NodeLabel = 0x0005,
    Location = 0x0006,
    HardwareVersion = 0x0007,
    HardwareVersionString = 0x0008,
    SoftwareVersion = 0x0009,
    SoftwareVersionString = 0x000A,
    ManufacturingDate = 0x000B,
    PartNumber = 0x000C,
    ProductURL = 0x000D,
    ProductLabel = 0x000E,
    SerialNumber = 0x000F,
    LocalConfigDisabled = 0x0010,
    Reachable = 0x0011,
    UniqueID = 0x0012,
    CapabilityMinima = 0x0013,
    ProductAppearance = 0x0014,
}

impl TryFrom<u32> for BasicInformationAttributes {
    type Error = MatterError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x0000 => Ok(BasicInformationAttributes::DataModelRevision),
            0x0001 => Ok(BasicInformationAttributes::VendorName),
            0x0002 => Ok(BasicInformationAttributes::VendorID),
            0x0003 => Ok(BasicInformationAttributes::ProductName),
            0x0004 => Ok(BasicInformationAttributes::ProductID),
            0x0005 => Ok(BasicInformationAttributes::NodeLabel),
            0x0006 => Ok(BasicInformationAttributes::Location),
            0x0007 => Ok(BasicInformationAttributes::HardwareVersion),
            0x0008 => Ok(BasicInformationAttributes::HardwareVersionString),
            0x0009 => Ok(BasicInformationAttributes::SoftwareVersion),
            0x000A => Ok(BasicInformationAttributes::SoftwareVersionString),
            0x000B => Ok(BasicInformationAttributes::ManufacturingDate),
            0x000C => Ok(BasicInformationAttributes::PartNumber),
            0x000D => Ok(BasicInformationAttributes::ProductURL),
            0x000E => Ok(BasicInformationAttributes::ProductLabel),
            0x000F => Ok(BasicInformationAttributes::SerialNumber),
            0x0010 => Ok(BasicInformationAttributes::LocalConfigDisabled),
            0x0011 => Ok(BasicInformationAttributes::Reachable),
            0x0012 => Ok(BasicInformationAttributes::UniqueID),
            0x0013 => Ok(BasicInformationAttributes::CapabilityMinima),
            0x0014 => Ok(BasicInformationAttributes::ProductAppearance),
            _ => Err(generic_error("No such value in Cluster Attributes..."))
        }
    }
}


#[derive(Clone)]
pub struct ProductAppearance {
    finish: ProductFinish,
    primary_color: ProductColor,
}


pub trait ClusterImplementation: Any {
    fn read_attributes(&self, attribute_path: AttributePath) -> Vec<AttributeReport>;

    fn as_any(&mut self) -> &mut dyn Any;

    // fn write_attribute(attribute_path: AttributePath, value: TLV);
    fn invoke_command(&mut self, command: CommandData) -> Vec<InvokeResponse>;
}


pub struct Device {
    pub endpoints_map: HashMap<u16, HashMap<u32, Box<dyn ClusterImplementation + Send>>>,
}


impl Device {
    pub fn new() -> Self {
        Self {
            endpoints_map: Default::default(),
        }
    }

    pub fn insert(&mut self, endpoint_id: u16, cluster_id: ClusterID, cluster: impl ClusterImplementation + std::marker::Send) {
        let mut endpoint_map = self.endpoints_map.entry(endpoint_id).or_insert_with(HashMap::new);
        endpoint_map.insert(cluster_id as u32, Box::new(cluster));
    }

    fn get<T: ClusterImplementation>(&mut self, endpoint_id: u16, cluster_id: ClusterID) -> Option<&mut T> {
        self.endpoints_map.get_mut(&endpoint_id)
            .map(|cluster_map| {
                cluster_map.get_mut(&(cluster_id as u32)).map(|cluster| cluster.as_any().downcast_mut())?
            })?
    }

    pub(crate) fn read_attributes(&mut self, attribute_path: AttributePath) -> Vec<AttributeReport> {
        let cluster_information = if let Specific(id) = attribute_path.cluster_id {
            format!("{:?}", ClusterID::from(id))
        } else {
            format!("{:?}", attribute_path.cluster_id)
        };
        log_debug!("[READ] Endpoint: {:?}, Cluster: {:?}, Attribute: {:?}", attribute_path.endpoint_id, cluster_information, attribute_path.attribute_id);
        match attribute_path.endpoint_id {
            QueryParameter::Wildcard => {
                let mut vec = vec![];
                for (endpoint_id, cluster_map) in &mut self.endpoints_map {
                    if let Specific(cluster_id) = attribute_path.cluster_id {
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
                    vec.push(
                        AttributeReport {
                            status: Some(AttributeStatus {
                                path: attribute_path,
                                status: Status { status: UnsupportedEndpoint as u8, cluster_status: 0 },
                            }),
                            data: None,
                        }
                    )
                }
                vec
            }
        }
    }

    pub(crate) fn invoke_command(&mut self, command: CommandData) -> Vec<InvokeResponse> {
        let command_path = command.path.clone();
        let cluster_information = if let Specific(id) = command_path.cluster_id {
            format!("{:?}", ClusterID::from(id))
        } else {
            format!("{:?}", command_path.cluster_id)
        };
        log_debug!("[INVOKE] Endpoint: {:?}, Cluster: {:?}, Command: {:?}", command_path.endpoint_id, cluster_information, command_path.command_id);

        match command_path.endpoint_id {
            QueryParameter::Wildcard => {
                let mut vec = vec![];
                for (endpoint_id, cluster_map) in &mut self.endpoints_map {
                    vec.extend(Self::invoke_cluster(cluster_map, *endpoint_id, command.clone()))
                }
                vec
            }
            QueryParameter::Specific(endpoint_id) => {
                let mut cluster_map = self.endpoints_map.get_mut(&endpoint_id);
                let mut vec = vec![];
                if let Some(cluster_map) = cluster_map {
                    vec.extend(Self::invoke_cluster(cluster_map, endpoint_id, command))
                } else {
                    vec.push(
                        InvokeResponse {
                            status: Some(CommandStatus {
                                path: command_path,
                                status: Status { status: UnsupportedEndpoint as u8, cluster_status: 0 },
                            }),
                            command: None,
                        }
                    )
                }
                vec
            }
        }
    }

    fn read_cluster(cluster_map: &mut HashMap<u32, Box<dyn ClusterImplementation + Send>>, endpoint_id: u16, attribute_path: AttributePath) -> Vec<AttributeReport> {
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
                    vec.push(
                        AttributeReport {
                            status: Some(AttributeStatus {
                                path: attribute_path,
                                status: Status { status: UnsupportedCluster as u8, cluster_status: 0 },
                            }),
                            data: None,
                        }
                    )
                }
            }
        }

        vec
    }

    fn invoke_cluster(cluster_map: &mut HashMap<u32, Box<dyn ClusterImplementation + Send>>, endpoint_id: u16, command: CommandData) -> Vec<InvokeResponse> {
        let mut vec = vec![];
        let command_path = command.path.clone();
        match command_path.cluster_id {
            QueryParameter::Wildcard => {
                for (cluster_id, cluster) in cluster_map {
                    let mut to_add = cluster.invoke_command(command.clone());
                    for a_r in &mut to_add {
                        a_r.set_cluster_id(*cluster_id);
                        a_r.set_endpoint_id(endpoint_id);
                    }
                    vec.extend(to_add);
                }
            }
            QueryParameter::Specific(cluster_id) => {
                if let Some(cluster) = cluster_map.get_mut(&cluster_id) {
                    let mut to_add = cluster.invoke_command(command.clone());
                    for a_r in &mut to_add {
                        a_r.set_cluster_id(cluster_id);
                        a_r.set_endpoint_id(endpoint_id);
                    }
                    vec.extend(to_add);
                } else {
                    vec.push(
                        InvokeResponse {
                            status: Some(CommandStatus {
                                path: command_path,
                                status: Status { status: UnsupportedCluster as u8, cluster_status: 0 },
                            }),
                            command: None,
                        }
                    )
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


impl From<RegulatoryLocationType> for ElementType {
    fn from(value: RegulatoryLocationType) -> Self {
        Unsigned8(value as u8)
    }
}

impl From<NetworkCommissioningStatus> for ElementType {
    fn from(value: NetworkCommissioningStatus) -> Self {
        Unsigned8(value as u8)
    }
}


pub mod wi_fi_security {
    pub const UNENCRYPTED: u8 = 0b1;
    pub const WEP: u8 = 0b10;
    pub const WPA_PERSONAL: u8 = 0b100;
    pub const WPA2_PERSONAL: u8 = 0b1000;
    pub const WPA3_PERSONAL: u8 = 0b10000;
}

