use crate::session::protocol::interaction::enums::QueryParameter;
use crate::session::protocol::interaction::information_blocks::attribute::report::AttributeReport;
use crate::session::protocol::interaction::information_blocks::attribute::Attribute;
use crate::session::protocol::interaction::information_blocks::AttributePath;
use crate::tlv::create_advanced_tlv;
use crate::tlv::element_type::ElementType;
use crate::tlv::element_type::ElementType::Structure;
use crate::tlv::tag_control::TagControl;
use crate::tlv::tag_number::TagNumber::Short;
use crate::utils::{generic_error, MatterError};


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
    pub capability_minima: CapabilityMinima,
}

impl ClusterImplementation for BasicInformationCluster {
    fn read_attributes(&self, attribute_path: AttributePath) -> Vec<AttributeReport> {
        match attribute_path.attribute_id {
            QueryParameter::Wildcard => todo!(""),
            QueryParameter::Specific(_) => todo!("")
        }
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
pub enum ProductFinish {
    Other = 0,
    Matter = 1,
    Satin = 2,
    Polished = 3,
    Rugged = 4,
    Fabric = 5,
}

#[repr(u8)]
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

pub struct ProductAppearance {
    finish: ProductFinish,
    primary_color: ProductColor,
}

pub struct CapabilityMinima {
    case_sessions_per_fabric: u16, // min = 3
    subscriptions_per_fabric: u16, // min = 3
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


pub trait ClusterImplementation {
    fn read_attributes(&self, attribute_path: AttributePath) -> Vec<AttributeReport>;


    // fn write_attribute(attribute_path: AttributePath, value: TLV);
    // fn invoke_command(command_path: CommandPath);
}
