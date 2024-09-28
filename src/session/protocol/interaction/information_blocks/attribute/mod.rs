pub(crate) mod report;
pub(crate) mod status;
pub(crate) mod data;

use crate::session::protocol::interaction::enums::GlobalStatusCode;
use crate::session::protocol::interaction::information_blocks::attribute::data::AttributeData;
use crate::session::protocol::interaction::information_blocks::attribute::report::AttributeReport;
use crate::session::protocol::interaction::information_blocks::attribute::status::{AttributeStatus, Status};
use crate::session::protocol::interaction::information_blocks::AttributePath;
use crate::tlv::element_type::ElementType;
use crate::tlv::tlv::TLV;

///
/// @author Mihael Berčič
/// @date 24. 9. 24
///
pub mod flags {
    pub const READ: u8 = 1;
    pub const WRITE: u8 = 1;
}

#[derive(Clone)]
pub struct Attribute<T> {
    pub id: u32,
    pub value: T,
}


impl<T: Into<ElementType>> Into<AttributeReport> for Attribute<T> {
    fn into(self) -> AttributeReport {
        AttributeReport {
            status: None,
            data: Some(AttributeData {
                data_version: 0,
                path: AttributePath::new(self.id),
                data: TLV::simple(self.value.into()),
            }),
        }
    }
}

impl<T> Into<AttributeReport> for Option<Attribute<T>>
    where Attribute<T>: Into<AttributeReport>
{
    fn into(self) -> AttributeReport {
        match self {
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




