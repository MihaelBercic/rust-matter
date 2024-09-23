use crate::session::protocol::interaction::device::{ClusterImplementation, QueryParameter};
use crate::session::protocol::interaction::information_blocks::AttributePath;
use crate::tlv::tlv::TLV;
use crate::tlv::{create_tlv, tlv_string, tlv_unsigned};
use crate::utils::{generic_error, MatterError};

///
/// @author Mihael Berčič
/// @date 23. 9. 24
///
struct BasicInformationCluster {
    data_model_revision: u16,
    vendor_name: String,
    vendor_id: u16,
    product_name: String,
    product_id: u16,
    node_label: String,
    location: String,
    hardware_version: u16,
    hardware_version_string: String,
    software_version: u32,
    software_version_string: String,
    manufacturing_date: Option<String>,
    part_number: Option<String>,
    product_url: Option<String>,
    product_label: Option<String>,
    serial_number: Option<String>,
    local_config_disabled: Option<bool>,
    reachable: Option<bool>,
    unique_id: Option<String>,
    product_appearance: Option<ProductAppearance>,
    capability_minima: CapabilityMinima,
}

impl ClusterImplementation for BasicInformationCluster {
    fn read_attribute(&self, attribute_path: AttributePath) -> TLV {
        match attribute_path.attribute_id {
            QueryParameter::Wildcard => todo!("So we return all attributes?"),
            QueryParameter::Specific(id) => {
                let attribute = ClusterAttributes::try_from(id).unwrap();
                match attribute {
                    ClusterAttributes::DataModelRevision => create_tlv(tlv_unsigned(self.data_model_revision)),
                    _ => create_tlv(tlv_string(self.location.to_string()))
                }
            }
        }
    }
}

enum ClusterAttributes {
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

impl TryFrom<u32> for ClusterAttributes {
    type Error = MatterError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x0000 => Ok(ClusterAttributes::DataModelRevision),
            0x0001 => Ok(ClusterAttributes::VendorName),
            0x0002 => Ok(ClusterAttributes::VendorID),
            0x0003 => Ok(ClusterAttributes::ProductName),
            0x0004 => Ok(ClusterAttributes::ProductID),
            0x0005 => Ok(ClusterAttributes::NodeLabel),
            0x0006 => Ok(ClusterAttributes::Location),
            0x0007 => Ok(ClusterAttributes::HardwareVersion),
            0x0008 => Ok(ClusterAttributes::HardwareVersionString),
            0x0009 => Ok(ClusterAttributes::SoftwareVersion),
            0x000A => Ok(ClusterAttributes::SoftwareVersionString),
            0x000B => Ok(ClusterAttributes::ManufacturingDate),
            0x000C => Ok(ClusterAttributes::PartNumber),
            0x000D => Ok(ClusterAttributes::ProductURL),
            0x000E => Ok(ClusterAttributes::ProductLabel),
            0x000F => Ok(ClusterAttributes::SerialNumber),
            0x0010 => Ok(ClusterAttributes::LocalConfigDisabled),
            0x0011 => Ok(ClusterAttributes::Reachable),
            0x0012 => Ok(ClusterAttributes::UniqueID),
            0x0013 => Ok(ClusterAttributes::CapabilityMinima),
            0x0014 => Ok(ClusterAttributes::ProductAppearance),
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