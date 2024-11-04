use crate::mdns::device_information::DeviceInformation;
use crate::session::protocol::interaction::cluster::capability_minima::CapabilityMinima;
use crate::session::protocol::interaction::cluster::{BasicInformationAttributes, ClusterImplementation, ProductAppearance};
use crate::session::protocol::interaction::enums::QueryParameter;
use crate::session::protocol::interaction::information_blocks::attribute::report::AttributeReport;
use crate::session::protocol::interaction::information_blocks::attribute::Attribute;
use crate::session::protocol::interaction::information_blocks::{AttributePath, CommandData, InvokeResponse};
use crate::session::session::Session;
use crate::session::Device;
use std::any::Any;

///
/// @author Mihael Berčič
/// @date 8. 10. 24
///
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
            vendor_name: Attribute {
                id: 0x0001,
                value: "Mihael Berčič".to_string(),
            },
            vendor_id: Attribute { id: 0x0002, value: 0xFFF1 },
            product_name: Attribute {
                id: 0x0003,
                value: "New Thermo".to_string(),
            },
            product_id: Attribute { id: 0x0004, value: 0x8000 },
            node_label: Attribute {
                id: 0x0005,
                value: "New Thermo".to_string(),
            },
            location: Attribute {
                id: 0x0006,
                value: "Living Room".to_string(),
            },
            hardware_version: Attribute { id: 0x0007, value: 1 },
            hardware_version_string: Attribute {
                id: 0x0008,
                value: "1".to_string(),
            },
            software_version: Attribute { id: 0x0009, value: 1 },
            software_version_string: Attribute {
                id: 0x000A,
                value: "1".to_string(),
            },
            manufacturing_date: None,
            part_number: None,
            product_url: None,
            product_label: None,
            serial_number: None,
            local_config_disabled: None,
            reachable: None,
            unique_id: None,
            product_appearance: None,
            capability_minima: Attribute {
                id: 0x0013,
                value: Default::default(),
            },
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
                let mut vec: Vec<AttributeReport> = vec![match attribute {
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
                    BasicInformationAttributes::ProductAppearance => panic!("Product Appearnce not yet implemented"),
                }];
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

    fn invoke_command(&mut self, command: CommandData, session: &mut Session, device: &mut DeviceInformation) -> Vec<InvokeResponse> {
        todo!()
    }
}
