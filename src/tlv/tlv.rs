use std::io::Cursor;

use byteorder::{ReadBytesExt, LE};
use p256::pkcs8::der::Writer;

use TagControl::{CommonProfile16, CommonProfile32, ContextSpecific8, FullyQualified48, FullyQualified64, ImplicitProfile16, ImplicitProfile32};

use crate::tlv::control::Control;
use crate::tlv::element_type::ElementType;
use crate::tlv::tag::Tag;
use crate::tlv::tag_control::TagControl;
use crate::tlv::tag_number::TagNumber;
use crate::tlv::tag_number::TagNumber::{Long, Medium, Short};
use crate::utils::MatterError;

///
/// @author Mihael Berčič
/// @date 2. 8. 24
///
#[derive(Clone, Debug)]
pub struct TLV {
    pub control: Control,
    pub tag: Tag,
}

impl TLV {
    pub fn simple(element_type: ElementType) -> Self {
        TLV {
            control: Control { tag_control: TagControl::Anonymous0, element_type },
            tag: Tag {
                vendor: None,
                profile: None,
                tag_number: None,
            },
        }
    }

    pub fn new(element_type: ElementType, tag_control: TagControl, tag: Tag) -> TLV {
        Self {
            control: Control { tag_control, element_type },
            tag,
        }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        let mut data = vec![];
        let control_byte: u8 = self.control.clone().into();
        let tag_data: Vec<u8> = self.tag.into();

        data.write_byte(control_byte).expect("Unable to write control byte...");
        data.extend(tag_data);
        let value: Option<Vec<u8>> = self.control.element_type.into();
        if let Some(value) = value {
            data.extend(value);
        }
        data
    }

    pub fn try_from_cursor(cursor: &mut Cursor<&[u8]>) -> Result<Self, MatterError> {
        let control_byte = cursor.read_u8()?;
        let tag_control = TagControl::from(control_byte >> 5);
        let mut vendor: Option<u16> = None;
        let mut profile: Option<u16> = None;
        let mut tag_number: Option<TagNumber> = None;
        match tag_control {
            ContextSpecific8 => tag_number = Some(Short(cursor.read_u8()?)),
            CommonProfile16 | ImplicitProfile16 => tag_number = Some(Medium(cursor.read_u16::<LE>()?)),
            CommonProfile32 | ImplicitProfile32 => tag_number = Some(Long(cursor.read_u32::<LE>()?)),
            FullyQualified48 => {
                vendor = Some(cursor.read_u16::<LE>()?);
                profile = Some(cursor.read_u16::<LE>()?);
                tag_number = Some(Medium(cursor.read_u16::<LE>()?));
            }
            FullyQualified64 => {
                vendor = Some(cursor.read_u16::<LE>()?);
                profile = Some(cursor.read_u16::<LE>()?);
                tag_number = Some(Long(cursor.read_u32::<LE>()?));
            }
            _ => {}
        }
        let tag = Tag { vendor, profile, tag_number };
        let element_type = control_byte & 0b11111;
        let element_type = ElementType::from_with_value(element_type, cursor)?;
        let control = Control { tag_control, element_type };
        Ok(TLV {
            control,
            tag,
        })
    }
}

impl From<TLV> for Vec<u8> {
    fn from(tlv: TLV) -> Self {
        let mut data = vec![];
        let control_byte: u8 = tlv.control.clone().into();
        let tag_data: Vec<u8> = tlv.tag.into();

        data.write_byte(control_byte).expect("Unable to write control byte...");
        data.extend(tag_data);
        let value: Option<Vec<u8>> = tlv.control.element_type.into();
        if let Some(value) = value {
            data.extend(value);
        }
        data
    }
}