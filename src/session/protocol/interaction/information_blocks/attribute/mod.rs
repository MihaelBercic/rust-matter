pub(crate) mod report;
pub(crate) mod status;
pub(crate) mod data;

use crate::session::protocol::interaction::enums::GlobalStatusCode;
use crate::session::protocol::interaction::information_blocks::attribute::data::AttributeData;
use crate::session::protocol::interaction::information_blocks::attribute::report::AttributeReport;
use crate::session::protocol::interaction::information_blocks::attribute::status::{AttributeStatus, Status};
use crate::session::protocol::interaction::information_blocks::AttributePath;
use crate::tlv::element_type::ElementType;
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::TLV;

///
/// @author Mihael Berčič
/// @date 24. 9. 24
///
pub mod flags {
    pub const READ: u8 = 1;
    pub const WRITE: u8 = 1;
}

#[derive(Clone, Default, Debug)]
pub struct Attribute<T> {
    pub id: u32,
    pub value: T,
}

impl<T: Into<ElementType>> From<Attribute<T>> for AttributeReport {
    fn from(value: Attribute<T>) -> Self {
        AttributeReport {
            status: None,
            data: Some(AttributeData {
                data_version: 1,
                path: AttributePath::new(value.id),
                data: TLV::new(value.value.into(), ContextSpecific8, Tag::simple(Short(2))),
            }),
        }
    }
}

impl<T> From<Option<Attribute<T>>> for AttributeReport
    where Attribute<T>: Into<AttributeReport>
{
    fn from(value: Option<Attribute<T>>) -> Self {
        match value {
            None => {
                AttributeReport {
                    status: Some(AttributeStatus {
                        path: Default::default(),
                        status: Status { status: GlobalStatusCode::UnsupportedAttribute as u8, cluster_status: 0 },
                    }),
                    data: None,
                }
            }
            Some(attribute) => attribute.into()
        }
    }
}