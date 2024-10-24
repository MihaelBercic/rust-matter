pub mod basic_commissioning_info;
pub mod basic_information;
pub mod capability_minima;
pub mod descriptor_cluster;
mod device_type;
pub mod enums;
pub mod general_commissioning;
mod icd_management;
pub mod network_commissioning;
pub mod network_info;
mod noc;
pub mod on_off;
pub mod operational_credentials;
pub use device_type::*;
pub use icd_management::*;
pub use noc::*;

mod fabric_descriptor;
pub use fabric_descriptor::*;

mod certification_declaration;
pub use certification_declaration::CertificationDeclaration;

use crate::log_debug;
use crate::session::protocol::interaction::cluster::basic_commissioning_info::BasicCommissioningInfo;
use crate::session::protocol::interaction::cluster::enums::{NetworkCommissioningStatus, ProductColor, ProductFinish, RegulatoryLocationType};
use crate::session::protocol::interaction::enums::GlobalStatusCode::{UnsupportedCluster, UnsupportedEndpoint};
use crate::session::protocol::interaction::enums::QueryParameter::Specific;
use crate::session::protocol::interaction::enums::{ClusterID, QueryParameter};
use crate::session::protocol::interaction::information_blocks::attribute::report::AttributeReport;
use crate::session::protocol::interaction::information_blocks::attribute::status::{AttributeStatus, Status};
use crate::session::protocol::interaction::information_blocks::{AttributePath, CommandData, CommandStatus, InvokeResponse};
use crate::session::session::Session;
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
            _ => Err(generic_error("No such value in Cluster Attributes...")),
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
    fn invoke_command(&mut self, command: CommandData, session: &mut Session) -> Vec<InvokeResponse>;
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
