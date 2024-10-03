use crate::session::protocol::interaction::enums::{ClusterID, QueryParameter};
use crate::session::protocol::interaction::information_blocks::attribute::report::AttributeReport;
use crate::session::protocol::interaction::information_blocks::attribute::Attribute;
use crate::session::protocol::interaction::information_blocks::AttributePath;
use crate::tlv::create_advanced_tlv;
use crate::tlv::element_type::ElementType;
use crate::tlv::element_type::ElementType::Structure;
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::TLV;
use crate::utils::{generic_error, MatterError};
use std::any::Any;
use std::collections::HashMap;
use std::sync::mpsc::{Receiver, Sender};

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
    // fn invoke_command(command_path: CommandPath);
}

enum AvailableCommands {
    Toggle,
    On,
    Off,
    Fade,
}

enum CommandEvent {
    On,
    Off,
    Toggle { new_value: bool },
    Fade { to: u8 },
}

enum AttributeChanges {
    OnOffChange { new_value: bool }
}

enum ChangeEvent {
    Attribute { endpoint_id: u8, change: AttributeChanges },
    Command { endpoint_id: u8, change: CommandEvent },
}

pub struct SampleOnOffCluster {
    on_off: Attribute<bool>,
    supported_commands: Vec<AvailableCommands>,
}


pub struct Device {
    endpoints_map: HashMap<u16, HashMap<u32, Box<dyn ClusterImplementation>>>,
    event_channel: (Sender<ChangeEvent>, Receiver<ChangeEvent>),
}

impl Device {
    pub fn get<T: ClusterImplementation>(&mut self, endpoint_id: u16, cluster_id: ClusterID) -> Option<&mut T> {
        self.endpoints_map.get_mut(&endpoint_id)
            .map(|cluster_map| {
                cluster_map.get_mut(&(cluster_id as u32)).map(|cluster| cluster.as_any().downcast_mut())?
            })?
    }

    pub fn read_attributes(&mut self, attribute_path: AttributePath) -> Vec<AttributeReport> {
        todo!()
    }
}

impl ClusterImplementation for SampleOnOffCluster {
    fn read_attributes(&self, attribute_path: AttributePath) -> Vec<AttributeReport> {
        todo!()
    }

    fn as_any(&mut self) -> &mut dyn Any {
        todo!()
    }
}