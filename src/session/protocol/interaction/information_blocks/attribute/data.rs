use crate::session::protocol::interaction::information_blocks::AttributePath;
use crate::tlv::element_type::ElementType;
use crate::tlv::element_type::ElementType::Structure;
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl::ContextSpecific8;
use crate::tlv::tag_number::TagNumber::Short;
use crate::tlv::tlv::Tlv;
use crate::utils::{bail_tlv, MatterError};

///
/// @author Mihael Berčič
/// @date 27. 9. 24
///
#[derive(Debug)]
pub struct AttributeData {
    pub data_version: u32,
    pub path: AttributePath,
    pub data: Tlv,
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
