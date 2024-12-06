use crate::{
    log_info,
    tlv::{
        element_type::ElementType::{self, *},
        tag::Tag,
        tag_control::TagControl::{self, ContextSpecific8},
        tag_number::TagNumber::Short,
        tlv::Tlv,
    },
    utils::{bail_tlv, tlv_error, MatterError},
};

use super::enums::{GlobalStatusCode, QueryParameter, QueryParameter::*};

#[derive(Clone)]
pub struct Attribute<const ID: u32, T: Into<ElementType>> {
    pub value: T,
}

pub struct AttributeReport {
    pub status: Option<AttributeStatus>,
    pub data: Option<AttributeData>,
}

pub struct AttributeStatus {
    pub path: AttributePath,
    pub status: Status,
}

pub struct Status {
    pub status: u8,
    pub cluster_status: u8,
}

pub struct AttributeData {
    pub data_version: u32,
    pub path: AttributePath,
    pub data: Tlv,
}

pub struct AttributePath {
    pub(crate) enable_tag_compression: bool,
    pub(crate) node_id: QueryParameter<u64>,
    pub(crate) endpoint_id: QueryParameter<u16>,
    pub(crate) cluster_id: QueryParameter<u32>,
    pub(crate) attribute_id: QueryParameter<u32>,
    pub(crate) list_index: Option<u16>,
}

impl<const ID: u32, T: Into<ElementType>> From<Attribute<ID, T>> for AttributeReport {
    fn from(value: Attribute<ID, T>) -> Self {
        AttributeReport {
            status: None,
            data: Some(AttributeData {
                data_version: 1,
                path: AttributePath {
                    enable_tag_compression: true,
                    node_id: QueryParameter::Wildcard,
                    endpoint_id: QueryParameter::Wildcard,
                    cluster_id: QueryParameter::Wildcard,
                    attribute_id: QueryParameter::Specific(ID),
                    list_index: None,
                },
                data: Tlv::new(value.value.into(), TagControl::ContextSpecific8, Tag::short(2)),
            }),
        }
    }
}

impl<const ID: u32, T: Into<ElementType>> From<Option<Attribute<ID, T>>> for AttributeReport {
    fn from(value: Option<Attribute<ID, T>>) -> Self {
        match value {
            None => AttributeReport {
                status: Some(AttributeStatus {
                    path: AttributePath {
                        enable_tag_compression: true,
                        node_id: QueryParameter::Wildcard,
                        endpoint_id: QueryParameter::Wildcard,
                        cluster_id: QueryParameter::Wildcard,
                        attribute_id: QueryParameter::Specific(ID),
                        list_index: None,
                    },
                    status: Status {
                        status: GlobalStatusCode::UnsupportedAttribute as u8,
                        cluster_status: 0,
                    },
                }),
                data: None,
            },
            Some(attribute) => attribute.into(),
        }
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

impl From<AttributeData> for ElementType {
    fn from(value: AttributeData) -> Self {
        Structure(vec![
            Tlv::new(value.data_version.into(), ContextSpecific8, Tag::short(0)),
            Tlv::new(value.path.into(), ContextSpecific8, Tag::short(1)),
            value.data,
        ])
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

impl TryFrom<ElementType> for AttributeData {
    type Error = MatterError;

    fn try_from(value: ElementType) -> Result<Self, Self::Error> {
        let mut path: Option<AttributePath> = None;
        let mut data: Option<Tlv> = None;
        let mut data_version: u32 = 1;

        let Structure(children) = value else { bail_tlv!("Incorrect tlv container") };

        for child in children {
            let clone = child.clone();
            let element_type = child.control.element_type;
            let Some(Short(tag)) = child.tag.tag_number else { bail_tlv!("Missing tag number") };
            match tag {
                0 => data_version = element_type.into_u32()?,
                1 => path = Some(AttributePath::try_from(element_type)?),
                2 => data = Some(clone),
                _ => todo!("IDK"),
            }
        }

        let Some(path) = path else { bail_tlv!("Missing path!") };
        let Some(data) = data else { bail_tlv!("Missing data!") };
        Ok(Self { data_version, path, data })
    }
}
