pub mod attribute;

use crate::session::protocol::interaction::enums::QueryParameter;
use crate::session::protocol::interaction::enums::QueryParameter::{Specific, Wildcard};
use crate::tlv::element_type::ElementType;
use crate::tlv::element_type::ElementType::List;
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::TLV;
use crate::utils::{tlv_error, MatterError};

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

impl TryFrom<TLV> for AttributePath {
    type Error = MatterError;

    fn try_from(value: TLV) -> Result<Self, Self::Error> {
        let mut attribute_path = Self {
            enable_tag_compression: false,
            node_id: Wildcard,
            endpoint_id: Wildcard,
            cluster_id: Wildcard,
            attribute_id: Wildcard,
            list_index: None,
        };

        let List(children) = value.control.element_type else {
            return Err(tlv_error("Incorrect TLV element type..."))
        };

        for child in children {
            let element_type = child.control.element_type;
            let Some(Short(tag_number)) = child.tag.tag_number else {
                return Err(tlv_error("Incorrect TLV tag number..."))
            };
            match tag_number {
                0 => attribute_path.enable_tag_compression = element_type.into_boolean()?,
                1 => attribute_path.node_id = Specific(element_type.into_u64()?),
                2 => attribute_path.endpoint_id = Specific(element_type.into_u16()?),
                3 => attribute_path.cluster_id = Specific(element_type.into_u32()?),
                4 => attribute_path.attribute_id = Specific(element_type.into_u32()?),
                5 => attribute_path.list_index = Some(element_type.into_u16()?),
                _ => return Err(tlv_error("Incorrect TLV tag number!"))
            }
        }

        Ok(attribute_path)
    }
}

impl From<AttributePath> for ElementType {
    fn from(value: AttributePath) -> Self {
        let mut vec = vec![TLV::new(value.enable_tag_compression.into(), ContextSpecific8, Tag::simple(Short(0)))];
        if let Specific(node_id) = value.node_id {
            vec.push(TLV::new(node_id.into(), ContextSpecific8, Tag::simple(Short(1))));
        }
        if let Specific(endpoint_id) = value.endpoint_id {
            vec.push(TLV::new(endpoint_id.into(), ContextSpecific8, Tag::simple(Short(2))));
        }

        if let Specific(cluster_id) = value.cluster_id {
            vec.push(TLV::new(cluster_id.into(), ContextSpecific8, Tag::simple(Short(3))));
        }

        if let Specific(attribute_id) = value.attribute_id {
            vec.push(TLV::new(attribute_id.into(), ContextSpecific8, Tag::simple(Short(4))));
        }

        if let Some(list_index) = value.list_index {
            vec.push(TLV::new(list_index.into(), ContextSpecific8, Tag::simple(Short(5))));
        }
        List(vec)
    }
}


#[derive(Clone, Debug)]
pub struct CommandPath {
    endpoint_id: QueryParameter<u16>,
    cluster_id: QueryParameter<u32>,
    command_id: QueryParameter<u32>,
}

impl TryFrom<TLV> for CommandPath {
    type Error = MatterError;

    fn try_from(value: TLV) -> Result<Self, Self::Error> {
        let mut command_path = CommandPath {
            endpoint_id: Wildcard,
            cluster_id: Wildcard,
            command_id: Wildcard,
        };
        let List(children) = value.control.element_type else {
            return Err(tlv_error("Incorrect TLV element type..."))
        };
        for child in children {
            let element_type = child.control.element_type;
            let Some(Short(tag_number)) = child.tag.tag_number else {
                return Err(tlv_error("Incorrect TLV tag number..."))
            };
            match tag_number {
                0 => command_path.endpoint_id = Specific(element_type.into_u16()?),
                1 => command_path.cluster_id = Specific(element_type.into_u32()?),
                2 => command_path.command_id = Specific(element_type.into_u32()?),
                _ => return Err(tlv_error("Incorrect TLV tag number!"))
            }
        }
        Ok(command_path)
    }
}

