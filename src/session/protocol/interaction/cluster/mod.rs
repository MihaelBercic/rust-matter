use crate::log_info;
use crate::session::protocol::interaction::enums::GlobalStatusCode::{UnsupportedCluster, UnsupportedEndpoint};
use crate::session::protocol::interaction::enums::QueryParameter::Specific;
use crate::session::protocol::interaction::enums::{ClusterID, QueryParameter};
use crate::session::protocol::interaction::information_blocks::attribute::report::AttributeReport;
use crate::session::protocol::interaction::information_blocks::attribute::status::{AttributeStatus, Status};
use crate::session::protocol::interaction::information_blocks::attribute::Attribute;
use crate::session::protocol::interaction::information_blocks::{AttributePath, CommandData, CommandPath, CommandStatus, InvokeResponse};
use crate::tlv::create_advanced_tlv;
use crate::tlv::element_type::ElementType;
use crate::tlv::element_type::ElementType::{Array, Structure, UTFString8, Unsigned8};
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl;
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::TLV;
use crate::utils::{generic_error, MatterError};
use std::any::Any;
use std::collections::HashMap;

pub struct BasicInformationCluster {
    pub data_model_revision: Attribute<u16>,
    pub vendor_name: Attribute<String>,
    pub vendor_id: Attribute<u16>,
    pub product_name: Attribute<String>,
    pub product_id: Attribute<u16>,
    pub node_label: Attribute<String>,
    pub location: Attribute<String>,
    pub hardware_version: Attribute<u16>,
    pub hardware_version_string: Attribute<String>,
    pub software_version: Attribute<u32>,
    pub software_version_string: Attribute<String>,
    pub manufacturing_date: Option<Attribute<String>>,
    pub part_number: Option<Attribute<String>>,
    pub product_url: Option<Attribute<String>>,
    pub product_label: Option<Attribute<String>>,
    pub serial_number: Option<Attribute<String>>,
    pub local_config_disabled: Option<Attribute<bool>>,
    pub reachable: Option<Attribute<bool>>,
    pub unique_id: Option<Attribute<String>>,
    pub product_appearance: Option<Attribute<ProductAppearance>>,
    pub capability_minima: Attribute<CapabilityMinima>,
}

impl BasicInformationCluster {
    pub fn new() -> Self {
        Self {
            data_model_revision: Attribute { id: 0x0000, value: 1 },
            vendor_name: Attribute { id: 0x0001, value: "Mihael Berčič".to_string() },
            vendor_id: Attribute { id: 0x0002, value: 0xFFF1 },
            product_name: Attribute { id: 0x0003, value: "New Thermo".to_string() },
            product_id: Attribute { id: 0x0004, value: 0x8000 },
            node_label: Attribute { id: 0x0005, value: "New Thermo".to_string() },
            location: Attribute { id: 0x0006, value: "Living Room".to_string() },
            hardware_version: Attribute { id: 0x0007, value: 1 },
            hardware_version_string: Attribute { id: 0x0008, value: "".to_string() },
            software_version: Attribute { id: 0x0009, value: 1 },
            software_version_string: Attribute { id: 0x000A, value: "".to_string() },
            manufacturing_date: None,
            part_number: None,
            product_url: None,
            product_label: None,
            serial_number: None,
            local_config_disabled: None,
            reachable: None,
            unique_id: None,
            product_appearance: None,
            capability_minima: Attribute { id: 0x0013, value: Default::default() },
        }
    }
}

impl ClusterImplementation for BasicInformationCluster {
    fn read_attributes(&self, attribute_path: AttributePath) -> Vec<AttributeReport> {
        match attribute_path.attribute_id {
            QueryParameter::Wildcard => {
                let mut reports = vec![
                    self.data_model_revision.clone().into(),
                    self.vendor_name.clone().into(),
                    self.vendor_id.clone().into(),
                    self.product_name.clone().into(),
                    self.product_id.clone().into(),
                    self.node_label.clone().into(),
                    self.location.clone().into(),
                    self.hardware_version.clone().into(),
                    self.hardware_version_string.clone().into(),
                    self.software_version.clone().into(),
                    self.software_version_string.clone().into(),
                    self.manufacturing_date.clone().into(),
                    self.part_number.clone().into(),
                    self.product_url.clone().into(),
                    self.product_label.clone().into(),
                    self.serial_number.clone().into(),
                    self.local_config_disabled.clone().into(),
                    self.reachable.clone().into(),
                    self.unique_id.clone().into(),
                    // self.product_appearance.clone().into(),
                    self.capability_minima.clone().into(),
                ];
                reports
            }
            QueryParameter::Specific(id) => {
                let attribute = BasicInformationAttributes::try_from(id).unwrap();
                let mut vec: Vec<AttributeReport> = vec![
                    match attribute {
                        BasicInformationAttributes::DataModelRevision => self.data_model_revision.clone().into(),
                        BasicInformationAttributes::VendorName => self.vendor_name.clone().into(),
                        BasicInformationAttributes::VendorID => self.vendor_id.clone().into(),
                        BasicInformationAttributes::ProductName => self.product_name.clone().into(),
                        BasicInformationAttributes::ProductID => self.product_id.clone().into(),
                        BasicInformationAttributes::NodeLabel => self.node_label.clone().into(),
                        BasicInformationAttributes::Location => self.location.clone().into(),
                        BasicInformationAttributes::HardwareVersion => self.hardware_version.clone().into(),
                        BasicInformationAttributes::HardwareVersionString => self.hardware_version_string.clone().into(),
                        BasicInformationAttributes::SoftwareVersion => self.software_version.clone().into(),
                        BasicInformationAttributes::SoftwareVersionString => self.software_version_string.clone().into(),
                        BasicInformationAttributes::ManufacturingDate => self.manufacturing_date.clone().into(),
                        BasicInformationAttributes::PartNumber => self.part_number.clone().into(),
                        BasicInformationAttributes::ProductURL => self.product_url.clone().into(),
                        BasicInformationAttributes::ProductLabel => self.product_label.clone().into(),
                        BasicInformationAttributes::SerialNumber => self.serial_number.clone().into(),
                        BasicInformationAttributes::LocalConfigDisabled => self.local_config_disabled.clone().into(),
                        BasicInformationAttributes::Reachable => self.reachable.clone().into(),
                        BasicInformationAttributes::UniqueID => self.unique_id.clone().into(),
                        BasicInformationAttributes::CapabilityMinima => self.capability_minima.clone().into(),
                        BasicInformationAttributes::ProductAppearance => panic!("Product Appearnce not yet implemented")
                    }
                ];
                for x in &mut vec {
                    x.set_attribute_id(id);
                }
                vec
            }
        }
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    fn invoke_command(&mut self, command: CommandData) -> Vec<InvokeResponse> {
        todo!()
    }
}


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


#[repr(u8)]
#[derive(Clone)]
pub enum ProductFinish {
    Other = 0,
    Matter = 1,
    Satin = 2,
    Polished = 3,
    Rugged = 4,
    Fabric = 5,
}

#[repr(u8)]
#[derive(Clone)]
pub enum ProductColor {
    Black = 0,
    Navy = 1,
    Green = 2,
    Teal = 3,
    Maroon = 4,
    Purple = 5,
    Olive = 6,
    Gray = 7,
    Blue = 8,
    Lime = 9,
    Aqua = 10,
    Red = 11,
    Fuchsia = 12,
    Yellow = 13,
    White = 14,
    Nickel = 15,
    Chrome = 16,
    Brass = 17,
    Copper = 18,
    Silver = 19,
    Gold = 20,
}

#[derive(Clone)]
pub struct ProductAppearance {
    finish: ProductFinish,
    primary_color: ProductColor,
}

#[derive(Clone)]
pub struct CapabilityMinima {
    case_sessions_per_fabric: u16, // min = 3
    subscriptions_per_fabric: u16, // min = 3
}

impl From<CapabilityMinima> for ElementType {
    fn from(value: CapabilityMinima) -> Self {
        Structure(
            vec![
                TLV::new(value.case_sessions_per_fabric.into(), TagControl::ContextSpecific8, Tag::simple(Short(0))),
                TLV::new(value.subscriptions_per_fabric.into(), TagControl::ContextSpecific8, Tag::simple(Short(1)))
            ]
        )
    }
}

impl Default for CapabilityMinima {
    fn default() -> Self {
        Self {
            case_sessions_per_fabric: 3,
            subscriptions_per_fabric: 3,
        }
    }
}

impl CapabilityMinima {
    pub fn as_element_type(&self) -> ElementType {
        Structure(
            vec![
                create_advanced_tlv(self.case_sessions_per_fabric.into(), TagControl::ContextSpecific8, Some(Short(0)), None, None),
                create_advanced_tlv(self.subscriptions_per_fabric.into(), TagControl::ContextSpecific8, Some(Short(1)), None, None),
            ]
        )
    }
}


pub trait ClusterImplementation: Any {
    fn read_attributes(&self, attribute_path: AttributePath) -> Vec<AttributeReport>;

    fn as_any(&mut self) -> &mut dyn Any;

    // fn write_attribute(attribute_path: AttributePath, value: TLV);
    fn invoke_command(&mut self, command: CommandData) -> Vec<InvokeResponse>;
}

#[derive(Clone)]
pub enum AvailableCommands {
    Toggle,
    On,
    Off,
    Fade,
}

pub enum CommandEvent {
    On,
    Off,
    Toggle { new_value: bool },
    Fade { to: u8 },
}

pub enum AttributeChanges {
    OnOffChange { new_value: bool }
}

pub enum ChangeEvent {
    Attribute { endpoint_id: u8, change: AttributeChanges },
    Command { endpoint_id: u8, change: CommandEvent },
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
        match attribute_path.endpoint_id {
            QueryParameter::Wildcard => {
                let mut vec = vec![];
                for (endpoint_id, cluster_map) in &mut self.endpoints_map {
                    vec.extend(Self::read_cluster(cluster_map, *endpoint_id, attribute_path.clone()))
                }
                vec
            }
            QueryParameter::Specific(endpoint_id) => {
                let mut cluster_map = self.endpoints_map.get_mut(&endpoint_id);
                let mut vec = vec![];
                if let Some(cluster_map) = cluster_map {
                    vec.extend(Self::read_cluster(cluster_map, endpoint_id, attribute_path))
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
                        a_r.set_endpoint_id(endpoint_id);
                    }
                    vec.extend(to_add);
                }
            }
            QueryParameter::Specific(cluster_id) => {
                if let Some(cluster) = cluster_map.get_mut(&cluster_id) {
                    let mut to_add = cluster.read_attributes(attribute_path.clone());
                    for a_r in &mut to_add {
                        a_r.set_cluster_id(cluster_id);
                        a_r.set_endpoint_id(endpoint_id);
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

    pub fn modify_cluster<'a, T: ClusterImplementation + Clone>(&mut self, endpoint_id: u16, cluster_id: ClusterID, c: fn(&mut T)) {
        if let Some(cluster) = self.get::<T>(endpoint_id, cluster_id) {
            c(cluster);
        }
    }
}

pub struct GeneralCommissioningCluster {
    bread_crumb: Attribute<u64>,
    basic_commissioning_info: Attribute<BasicCommissioningInfo>,
    regulatory_config: Attribute<RegulatoryLocationType>,
    location_capability: Attribute<RegulatoryLocationType>,
    supports_concurrent_connection: Attribute<bool>,
}

impl GeneralCommissioningCluster {
    pub fn new() -> Self {
        Self {
            bread_crumb: Attribute { id: 0x00, value: 0 },
            basic_commissioning_info: Attribute {
                id: 0x01,
                value: BasicCommissioningInfo {
                    fail_safe_expiry_length_seconds: 900,
                    max_cumulative_failsafe_seconds: 900,
                },
            },
            regulatory_config: Attribute { id: 0x02, value: RegulatoryLocationType::Indoor },
            location_capability: Attribute { id: 0x03, value: RegulatoryLocationType::IndoorOutdoor },
            supports_concurrent_connection: Attribute { id: 0x04, value: true },
        }
    }
}

impl ClusterImplementation for GeneralCommissioningCluster {
    fn read_attributes(&self, attribute_path: AttributePath) -> Vec<AttributeReport> {
        match attribute_path.attribute_id {
            QueryParameter::Wildcard => {
                vec![
                    self.bread_crumb.clone().into(),
                    self.basic_commissioning_info.clone().into(),
                    self.regulatory_config.clone().into(),
                    self.location_capability.clone().into(),
                    self.supports_concurrent_connection.clone().into(),
                ]
            }
            QueryParameter::Specific(attribute_id) => {
                vec![
                    match attribute_id {
                        0 => self.bread_crumb.clone().into(),
                        1 => self.basic_commissioning_info.clone().into(),
                        2 => self.regulatory_config.clone().into(),
                        3 => self.location_capability.clone().into(),
                        4 => self.supports_concurrent_connection.clone().into(),
                        _ => todo!("")
                    }
                ]
            }
        }
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    fn invoke_command(&mut self, command: CommandData) -> Vec<InvokeResponse> {
        let command_path = command.path;
        let command_id = command_path.command_id;
        let mut vec = vec![
            InvokeResponse {
                command: Some(
                    CommandData {
                        path: CommandPath::new(Specific(1)),
                        fields: Some(
                            TLV::simple(Structure(vec![
                                TLV::new(Unsigned8(0), ContextSpecific8, Tag::simple(Short(0))),
                                TLV::new(UTFString8(String::from("")), ContextSpecific8, Tag::simple(Short(1))),
                            ]))
                        ),
                    }
                ),
                status: None
            }
        ];
        log_info!("Invoking a command!");
        match command_id {
            QueryParameter::Wildcard => {
                log_info!("Invoking all commands!")
            }
            QueryParameter::Specific(command_id) => {
                log_info!("Invoking a specific command! {}", command_id);
            }
        }
        vec
    }
}

pub enum CommissioningError {
    Ok = 0,
    ValueOutsideRange = 1,
    InvalidAuthentication = 2,
    NoFailSafe = 3,
    BusyWithOtherAdmin = 4,
}

#[derive(Clone)]
#[repr(u8)]
pub enum RegulatoryLocationType {
    Indoor = 0,
    Outdoor = 1,
    IndoorOutdoor = 2,
}

#[derive(Clone)]
pub struct BasicCommissioningInfo {
    fail_safe_expiry_length_seconds: u16,
    max_cumulative_failsafe_seconds: u16,
}

impl From<BasicCommissioningInfo> for ElementType {
    fn from(value: BasicCommissioningInfo) -> Self {
        Structure(
            vec![
                TLV::new(value.fail_safe_expiry_length_seconds.into(), ContextSpecific8, Tag::simple(Short(0))),
                TLV::new(value.max_cumulative_failsafe_seconds.into(), ContextSpecific8, Tag::simple(Short(1))),
            ]
        )
    }
}

impl From<RegulatoryLocationType> for ElementType {
    fn from(value: RegulatoryLocationType) -> Self {
        Unsigned8(value as u8)
    }
}

pub struct NetworkCommissioningCluster {
    max_networks: Attribute<u8>,
    networks: Attribute<Vec<NetworkInfo>>,
    scan_max_seconds: Attribute<u8>,
    connect_max_seconds: Attribute<u8>,
    interface_enabled: Attribute<bool>,
    last_networking_status: Attribute<NetworkCommissioningStatus>,
    last_network_id: Attribute<Vec<u8>>,
    last_connect_error: Attribute<i32>,
}

impl NetworkCommissioningCluster {
    pub fn new() -> Self {
        Self {
            max_networks: Attribute { id: 0x0000, value: 1 },
            networks: Attribute { id: 0x0001, value: vec![] },
            scan_max_seconds: Attribute { id: 0x0002, value: 60 },
            connect_max_seconds: Attribute { id: 0x0003, value: 60 },
            interface_enabled: Attribute { id: 0, value: true },
            last_networking_status: Attribute { id: 0, value: NetworkCommissioningStatus::Success },
            last_network_id: Attribute { id: 0, value: vec![12, 12, 3, 120, 0, 03, 0, 01, 20, 3] },
            last_connect_error: Attribute { id: 0, value: 0 },
        }
    }
}

impl ClusterImplementation for NetworkCommissioningCluster {
    fn read_attributes(&self, attribute_path: AttributePath) -> Vec<AttributeReport> {
        match attribute_path.attribute_id {
            QueryParameter::Wildcard => {
                vec![
                    self.max_networks.clone().into(),
                    self.networks.clone().into(),
                    self.scan_max_seconds.clone().into(),
                    self.connect_max_seconds.clone().into(),
                    self.interface_enabled.clone().into(),
                    self.last_networking_status.clone().into(),
                    self.last_network_id.clone().into(),
                    self.last_connect_error.clone().into(),
                ]
            }
            QueryParameter::Specific(attribute_id) => {
                vec![match attribute_id {
                    0x0000 => self.max_networks.clone().into(),
                    0x0001 => self.networks.clone().into(),
                    0x0002 => self.scan_max_seconds.clone().into(),
                    0x0003 => self.connect_max_seconds.clone().into(),
                    0x0004 => self.interface_enabled.clone().into(),
                    0x0005 => self.last_networking_status.clone().into(),
                    0x0006 => self.last_network_id.clone().into(),
                    0x0007 => self.last_connect_error.clone().into(),
                    _ => Attribute { id: 65532, value: 1 }.into()
                }]
            }
        }
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    fn invoke_command(&mut self, command: CommandData) -> Vec<InvokeResponse> {
        todo!()
    }
}

pub enum Features {
    Wifi = 0,
    Thread = 1,
    Ethernet = 2,
}

pub enum WiFiBand {
    WiFi2G4 = 0,
    WiFi3G5 = 1,
    WiFi5G = 2,
    WiFi6G = 3,
    WiFi60G = 4,
    WiFi1G = 5,
}

#[derive(Clone)]
pub enum NetworkCommissioningStatus {
    Success = 0,
    OutOfRange = 1,
    BoundsExceeded = 2,
    NetworkIDNotFound = 3,
    DuplicateNetworkID = 4,
    NetworkNotFound = 5,
    RegulatoryError = 6,
    AuthFailure = 7,
    UnsupportedSecurity = 8,
    OtherConnectionFailure = 9,
    IPv6Failed = 10,
    IPBindFailed = 11,
    UnknownError = 12,
}

impl From<NetworkCommissioningStatus> for ElementType {
    fn from(value: NetworkCommissioningStatus) -> Self {
        Unsigned8(value as u8)
    }
}

#[derive(Clone)]
pub struct NetworkInfo {
    network_id: Vec<u8>,
    connected: bool,
}

impl From<NetworkInfo> for ElementType {
    fn from(value: NetworkInfo) -> Self {
        Structure(
            vec![
                TLV::new(value.network_id.clone().into(), ContextSpecific8, Tag::simple(Short(0))),
                TLV::new(value.connected.clone().into(), ContextSpecific8, Tag::simple(Short(1))),
            ]
        )
    }
}

pub mod wi_fi_security {
    pub const UNENCRYPTED: u8 = 0b1;
    pub const WEP: u8 = 0b10;
    pub const WPA_PERSONAL: u8 = 0b100;
    pub const WPA2_PERSONAL: u8 = 0b1000;
    pub const WPA3_PERSONAL: u8 = 0b10000;
}

impl From<Vec<NetworkInfo>> for ElementType {
    fn from(value: Vec<NetworkInfo>) -> Self {
        let mut vec = vec![];
        for x in value {
            vec.push(TLV::simple(x.into()))
        }
        Array(vec)
    }
}