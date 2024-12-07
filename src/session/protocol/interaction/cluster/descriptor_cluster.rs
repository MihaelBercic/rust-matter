use crate::mdns::device_information::Details;
use crate::session::protocol::interaction::cluster::ClusterImplementation;
use crate::session::protocol::interaction::enums::QueryParameter;
use crate::session::protocol::interaction::information_blocks::attribute::report::AttributeReport;
use crate::session::protocol::interaction::information_blocks::attribute::Attribute;
use crate::session::protocol::interaction::information_blocks::{AttributePath, CommandData, InvokeResponse};
use crate::session::session::Session;
use crate::tlv::tag::Tag;
use std::any::Any;

use super::DeviceType;

///
/// @author Mihael Berčič
/// @date 10. 10. 24
///
pub struct DescriptorCluster {
    pub device_type_list: Attribute<Vec<DeviceType>>,
    pub server_list: Attribute<Vec<u32>>,
    pub client_list: Attribute<Vec<u32>>,
    pub parts_list: Attribute<Vec<u32>>,
    pub tag_list: Attribute<Vec<u32>>,
}

impl DescriptorCluster {
    pub fn new() -> Self {
        Self {
            device_type_list: Attribute {
                id: 0,
                value: vec![DeviceType { id: 0x0100, revision: 1 }],
            },
            server_list: Attribute {
                id: 1,
                value: vec![0x0006, 0x0028, 0x0030, 0x0031, 0x003E, 0x001D],
            },
            client_list: Default::default(),
            parts_list: Attribute { id: 3, value: vec![0, 1] },
            tag_list: Default::default(),
        }
    }
}

impl ClusterImplementation for DescriptorCluster {
    fn read_attributes(&self, attribute_path: AttributePath) -> Vec<AttributeReport> {
        match attribute_path.attribute_id {
            QueryParameter::Wildcard => {
                vec![
                    self.device_type_list.clone().into(),
                    self.server_list.clone().into(),
                    self.client_list.clone().into(),
                    self.parts_list.clone().into(),
                    self.tag_list.clone().into(),
                ]
            }
            QueryParameter::Specific(id) => {
                vec![match id {
                    0 => self.device_type_list.clone().into(),
                    1 => self.server_list.clone().into(),
                    2 => self.client_list.clone().into(),
                    3 => self.parts_list.clone().into(),
                    4 => self.tag_list.clone().into(),
                    _ => panic!("Okay not configured for this id..."),
                }]
            }
        }
    }

    fn as_any(&mut self) -> &mut dyn Any {
        todo!()
    }

    fn invoke_command(&mut self, command: CommandData, session: &mut Session, device: &mut Details) -> Vec<InvokeResponse> {
        todo!()
    }
}

pub struct SemanticTag {
    pub mfg_code: Option<u16>,
    pub namespace_id: String,
    pub tag: Tag,
    pub label: Option<String>,
}
