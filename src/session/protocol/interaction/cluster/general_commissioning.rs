use crate::log_info;
use crate::session::protocol::interaction::cluster::{BasicCommissioningInfo, ClusterImplementation, RegulatoryLocationType};
use crate::session::protocol::interaction::enums::QueryParameter;
use crate::session::protocol::interaction::enums::QueryParameter::Specific;
use crate::session::protocol::interaction::information_blocks::attribute::report::AttributeReport;
use crate::session::protocol::interaction::information_blocks::attribute::Attribute;
use crate::session::protocol::interaction::information_blocks::{AttributePath, CommandData, CommandPath, InvokeResponse};
use crate::session::session::Session;
use crate::tlv::element_type::ElementType::{Structure, UTFString8, Unsigned8};
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::Tlv;
use std::any::Any;

///
/// @author Mihael Berčič
/// @date 8. 10. 24
///
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
            regulatory_config: Attribute {
                id: 0x02,
                value: RegulatoryLocationType::Indoor,
            },
            location_capability: Attribute {
                id: 0x03,
                value: RegulatoryLocationType::IndoorOutdoor,
            },
            supports_concurrent_connection: Attribute { id: 0x04, value: true },
        }
    }

    fn arm_fail_safe(&mut self, input: Option<Tlv>) -> InvokeResponse {
        // TODO: Not fake it...
        InvokeResponse {
            command: Some(CommandData {
                path: CommandPath::new(Specific(1)),
                fields: Some(Tlv::simple(Structure(vec![
                    Tlv::new(Unsigned8(0), ContextSpecific8, Tag::short(0)),
                    Tlv::new(UTFString8(String::from("")), ContextSpecific8, Tag::short(1)),
                ]))),
            }),
            status: None,
        }
    }

    fn set_regulatory_config(&mut self, input: Option<Tlv>) -> InvokeResponse {
        InvokeResponse {
            command: Some(CommandData {
                path: CommandPath::new(Specific(3)),
                fields: Some(Tlv::simple(Structure(vec![
                    Tlv::new(Unsigned8(0), ContextSpecific8, Tag::short(0)),
                    Tlv::new(UTFString8(String::from("")), ContextSpecific8, Tag::short(1)),
                ]))),
            }),
            status: None,
        }
    }

    fn commissioning_complete(&mut self, input: Option<Tlv>) -> InvokeResponse {
        InvokeResponse {
            command: Some(CommandData {
                path: CommandPath::new(Specific(5)),
                fields: Some(Tlv::simple(Structure(vec![
                    Tlv::new(Unsigned8(0), ContextSpecific8, Tag::short(0)),
                    Tlv::new(UTFString8(String::from("")), ContextSpecific8, Tag::short(1)),
                ]))),
            }),
            status: None,
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
                vec![match attribute_id {
                    0 => self.bread_crumb.clone().into(),
                    1 => self.basic_commissioning_info.clone().into(),
                    2 => self.regulatory_config.clone().into(),
                    3 => self.location_capability.clone().into(),
                    4 => self.supports_concurrent_connection.clone().into(),
                    _ => todo!(""),
                }]
            }
        }
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    fn invoke_command(&mut self, command: CommandData, session: &mut Session) -> Vec<InvokeResponse> {
        let command_path = command.path;
        let command_id = command_path.command_id;
        let mut vec = vec![];
        match command_id {
            QueryParameter::Wildcard => {
                log_info!("Invoking all commands!")
            }
            QueryParameter::Specific(command_id) => match command_id {
                0 => vec.push(self.arm_fail_safe(command.fields)),
                2 => vec.push(self.set_regulatory_config(command.fields)),
                4 => vec.push(self.commissioning_complete(command.fields)),
                _ => {}
            },
        }
        vec
    }
}
