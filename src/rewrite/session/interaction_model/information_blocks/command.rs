use crate::{
    rewrite::session::interaction_model::enums::QueryParameter::{self, *},
    tlv::{element_type::ElementType, tag::Tag, tag_control::TagControl, tag_number::TagNumber, tlv::Tlv},
    utils::{bail_tlv, MatterError},
};

use super::attribute::Status;

#[derive(Clone, Debug)]
pub struct CommandPath {
    pub endpoint_id: QueryParameter<u16>,
    pub cluster_id: QueryParameter<u32>,
    pub command_id: QueryParameter<u32>,
}

#[derive(Debug, Clone)]
pub struct CommandData {
    pub path: CommandPath,
    pub fields: Option<Tlv>,
}

pub struct CommandStatus {
    pub path: CommandPath,
    pub status: Status,
}

pub struct InvokeResponse {
    pub command: Option<CommandData>,
    pub status: Option<CommandStatus>,
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
        let ElementType::List(children) = value else { bail_tlv!("Incorrect element type.") };

        for child in children {
            let element_type = child.control.element_type;
            let Some(TagNumber::Short(tag_number)) = child.tag.tag_number else {
                bail_tlv!("Incorrect tag number...")
            };
            match tag_number {
                0 => command_path.endpoint_id = Specific(element_type.into_u16()?),
                1 => command_path.cluster_id = Specific(element_type.into_u32()?),
                2 => command_path.command_id = Specific(element_type.into_u32()?),
                _ => bail_tlv!("Incorrect TLV tag number!"),
            }
        }
        Ok(command_path)
    }
}

impl From<CommandPath> for ElementType {
    fn from(value: CommandPath) -> Self {
        let mut vec = vec![];
        if let Specific(endpoint_id) = value.endpoint_id {
            vec.push(Tlv::new(endpoint_id.into(), TagControl::ContextSpecific8, Tag::short(0)));
        }

        if let Specific(cluster_id) = value.cluster_id {
            vec.push(Tlv::new(cluster_id.into(), TagControl::ContextSpecific8, Tag::short(1)));
        }

        if let Specific(attribute_id) = value.command_id {
            vec.push(Tlv::new(attribute_id.into(), TagControl::ContextSpecific8, Tag::short(2)));
        }
        ElementType::List(vec)
    }
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
            bail_tlv!("Incorrect data structure!")
        };

        for child in children {
            let clone = child.clone();
            let element_type = child.control.element_type;
            let Some(TagNumber::Short(tag_number)) = child.tag.tag_number else {
                bail_tlv!("Incorrect TLV tag number...")
            };
            match tag_number {
                0 => command_data.path = CommandPath::try_from(element_type)?,
                1 => command_data.fields = Some(clone),
                _ => bail_tlv!("Incorrect TLV tag number..."),
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
            children.push(Tlv::new(command.try_into()?, TagControl::ContextSpecific8, Tag::short(0)));
        }
        if let Some(status) = value.status {
            children.push(Tlv::new(status.try_into()?, TagControl::ContextSpecific8, Tag::short(1)));
        }
        Ok(ElementType::Structure(children))
    }
}

impl TryFrom<CommandData> for ElementType {
    type Error = MatterError;

    fn try_from(value: CommandData) -> Result<Self, Self::Error> {
        let mut children = vec![Tlv::new(value.path.into(), TagControl::ContextSpecific8, Tag::short(0))];
        if let Some(mut fields) = value.fields {
            fields.tag.tag_number = Some(TagNumber::Short(1));
            fields.control.tag_control = TagControl::ContextSpecific8;
            children.push(fields)
        }
        Ok(ElementType::Structure(children))
    }
}

impl TryFrom<CommandStatus> for ElementType {
    type Error = MatterError;

    fn try_from(value: CommandStatus) -> Result<Self, Self::Error> {
        Ok(ElementType::Structure(vec![
            Tlv::new(value.path.into(), TagControl::ContextSpecific8, Tag::short(0)),
            Tlv::new(value.status.into(), TagControl::ContextSpecific8, Tag::short(1)),
        ]))
    }
}
