pub mod attribute;

use crate::log_error;
use crate::session::protocol::interaction::enums::QueryParameter;
use crate::session::protocol::interaction::enums::QueryParameter::{Specific, Wildcard};
use crate::session::protocol::interaction::information_blocks::attribute::status::Status;
use crate::tlv::element_type::ElementType;
use crate::tlv::element_type::ElementType::{List, Structure};
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::Tlv;
use crate::utils::{bail_tlv, tlv_error, MatterError};

///
/// @author Mihael Berčič
/// @date 23. 9. 24
///
#[derive(Clone, Debug)]
pub struct AttributePath {
    pub(crate) enable_tag_compression: bool,
    pub(crate) node_id: QueryParameter<u64>,
    pub(crate) endpoint_id: QueryParameter<u16>,
    pub(crate) cluster_id: QueryParameter<u32>,
    pub(crate) attribute_id: QueryParameter<u32>,
    pub(crate) list_index: Option<u16>,
}

impl AttributePath {
    pub fn new(attribute_id: u32) -> Self {
        Self {
            attribute_id: Specific(attribute_id),
            ..Default::default()
        }
    }
}

impl Default for AttributePath {
    fn default() -> Self {
        Self {
            enable_tag_compression: false,
            node_id: Wildcard,
            endpoint_id: Wildcard,
            cluster_id: Wildcard,
            attribute_id: Wildcard,
            list_index: None,
        }
    }
}

impl TryFrom<ElementType> for AttributePath {
    type Error = MatterError;

    fn try_from(value: ElementType) -> Result<Self, Self::Error> {
        let mut attribute_path = Self {
            enable_tag_compression: false,
            node_id: Wildcard,
            endpoint_id: Wildcard,
            cluster_id: Wildcard,
            attribute_id: Wildcard,
            list_index: None,
        };

        let List(children) = value else { bail_tlv!("Incorrect container.") };

        for child in children {
            let element_type = child.control.element_type;
            let Some(Short(tag_number)) = child.tag.tag_number else {
                return Err(tlv_error("Incorrect TLV tag number..."));
            };
            match tag_number {
                0 => attribute_path.enable_tag_compression = element_type.into_boolean()?,
                1 => {
                    attribute_path.node_id = match element_type.into_u64() {
                        Err(_) => Wildcard,
                        Ok(id) => Specific(id),
                    }
                }
                2 => {
                    attribute_path.endpoint_id = match element_type.into_u16() {
                        Err(_) => Wildcard,
                        Ok(id) => Specific(id),
                    }
                }
                3 => {
                    attribute_path.cluster_id = match element_type.into_u32() {
                        Err(_) => Wildcard,
                        Ok(id) => Specific(id),
                    }
                }
                4 => {
                    attribute_path.attribute_id = match element_type.into_u32() {
                        Err(_) => Wildcard,
                        Ok(id) => Specific(id),
                    }
                }
                5 => attribute_path.list_index = element_type.into_u16_optional()?,
                _ => return Err(tlv_error("Incorrect TLV tag number!")),
            }
        }

        Ok(attribute_path)
    }
}

impl From<AttributePath> for ElementType {
    fn from(value: AttributePath) -> Self {
        let mut vec = vec![Tlv::new(value.enable_tag_compression.into(), ContextSpecific8, Tag::short(0))];
        if let Specific(node_id) = value.node_id {
            vec.push(Tlv::new(node_id.into(), ContextSpecific8, Tag::short(1)));
        }
        if let Specific(endpoint_id) = value.endpoint_id {
            vec.push(Tlv::new(endpoint_id.into(), ContextSpecific8, Tag::short(2)));
        }

        if let Specific(cluster_id) = value.cluster_id {
            vec.push(Tlv::new(cluster_id.into(), ContextSpecific8, Tag::short(3)));
        }

        if let Specific(attribute_id) = value.attribute_id {
            vec.push(Tlv::new(attribute_id.into(), ContextSpecific8, Tag::short(4)));
        }

        if let Some(list_index) = value.list_index {
            vec.push(Tlv::new(list_index.into(), ContextSpecific8, Tag::short(5)));
        }
        List(vec)
    }
}

#[derive(Clone, Debug)]
pub struct CommandPath {
    pub endpoint_id: QueryParameter<u16>,
    pub cluster_id: QueryParameter<u32>,
    pub command_id: QueryParameter<u32>,
}

impl CommandPath {
    pub fn new(command_id: QueryParameter<u32>) -> Self {
        Self {
            endpoint_id: Wildcard,
            cluster_id: QueryParameter::Wildcard,
            command_id,
        }
    }
}

impl TryFrom<ElementType> for CommandPath {
    type Error = MatterError;

    fn try_from(value: ElementType) -> Result<Self, Self::Error> {
        let mut command_path = CommandPath {
            endpoint_id: Wildcard,
            cluster_id: Wildcard,
            command_id: Wildcard,
        };
        let List(children) = value else {
            return Err(tlv_error("Incorrect TLV element type..."));
        };
        for child in children {
            let element_type = child.control.element_type;
            let Some(Short(tag_number)) = child.tag.tag_number else {
                return Err(tlv_error("Incorrect TLV tag number..."));
            };
            match tag_number {
                0 => command_path.endpoint_id = Specific(element_type.into_u16()?),
                1 => command_path.cluster_id = Specific(element_type.into_u32()?),
                2 => command_path.command_id = Specific(element_type.into_u32()?),
                _ => return Err(tlv_error("Incorrect TLV tag number!")),
            }
        }
        Ok(command_path)
    }
}

impl From<CommandPath> for ElementType {
    fn from(value: CommandPath) -> Self {
        let mut vec = vec![];
        if let Specific(endpoint_id) = value.endpoint_id {
            vec.push(Tlv::new(endpoint_id.into(), ContextSpecific8, Tag::short(0)));
        }

        if let Specific(cluster_id) = value.cluster_id {
            vec.push(Tlv::new(cluster_id.into(), ContextSpecific8, Tag::short(1)));
        }

        if let Specific(attribute_id) = value.command_id {
            vec.push(Tlv::new(attribute_id.into(), ContextSpecific8, Tag::short(2)));
        }
        List(vec)
    }
}

#[derive(Debug, Clone)]
pub struct CommandData {
    pub path: CommandPath,
    pub fields: Option<Tlv>,
}

pub struct InvokeResponse {
    pub command: Option<CommandData>,
    pub status: Option<CommandStatus>,
}

impl InvokeResponse {
    pub fn set_endpoint_id(&mut self, id: u16) {
        if let Some(status) = &mut self.status {
            status.path.endpoint_id = Specific(id);
        }
        if let Some(data) = &mut self.command {
            data.path.endpoint_id = Specific(id);
        }
    }

    pub fn set_cluster_id(&mut self, id: u32) {
        if let Some(status) = &mut self.status {
            status.path.cluster_id = Specific(id);
        }
        if let Some(data) = &mut self.command {
            data.path.cluster_id = Specific(id);
        }
    }

    pub fn set_attribute_id(&mut self, id: u32) {
        if let Some(status) = &mut self.status {
            status.path.command_id = Specific(id);
        }
        if let Some(data) = &mut self.command {
            data.path.command_id = Specific(id);
        }
    }
}

pub struct CommandStatus {
    pub path: CommandPath,
    pub status: Status,
}

impl TryFrom<Tlv> for CommandData {
    type Error = MatterError;

    fn try_from(value: Tlv) -> Result<Self, Self::Error> {
        let mut command_data = Self {
            path: CommandPath {
                endpoint_id: QueryParameter::Wildcard,
                cluster_id: QueryParameter::Wildcard,
                command_id: QueryParameter::Wildcard,
            },
            fields: None,
        };
        let ElementType::Structure(children) = value.control.element_type else {
            return Err(tlv_error("Incorrect data structure!"));
        };
        for child in children {
            let clone = child.clone();
            let element_type = child.control.element_type;
            let Some(Short(tag_number)) = child.tag.tag_number else {
                return Err(tlv_error("Incorrect TLV tag number..."));
            };
            match tag_number {
                0 => command_data.path = CommandPath::try_from(element_type)?,
                1 => command_data.fields = Some(clone),
                _ => Err(tlv_error("Incorrect TLV tag number!"))?,
            }
        }
        Ok(command_data)
    }
}

impl TryFrom<InvokeResponse> for ElementType {
    type Error = MatterError;

    fn try_from(value: InvokeResponse) -> Result<Self, Self::Error> {
        let mut children = vec![];
        if let Some(command) = value.command {
            children.push(Tlv::new(command.try_into()?, ContextSpecific8, Tag::short(0)));
        }
        if let Some(status) = value.status {
            children.push(Tlv::new(status.try_into()?, ContextSpecific8, Tag::short(1)));
        }
        Ok(Structure(children))
    }
}

impl TryFrom<CommandData> for ElementType {
    type Error = MatterError;

    fn try_from(value: CommandData) -> Result<Self, Self::Error> {
        let mut children = vec![Tlv::new(value.path.into(), ContextSpecific8, Tag::short(0))];
        if let Some(mut fields) = value.fields {
            fields.tag.tag_number = Some(Short(1));
            fields.control.tag_control = ContextSpecific8;
            children.push(fields)
        }
        Ok(Structure(children))
    }
}

impl TryFrom<CommandStatus> for ElementType {
    type Error = MatterError;

    fn try_from(value: CommandStatus) -> Result<Self, Self::Error> {
        Ok(Structure(vec![
            Tlv::new(value.path.into(), ContextSpecific8, Tag::short(0)),
            Tlv::new(value.status.into(), ContextSpecific8, Tag::short(1)),
        ]))
    }
}
