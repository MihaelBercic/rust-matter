use byteorder::{LittleEndian, WriteBytesExt};
use p256::pkcs8::der::Writer;

use crate::tlv::tag_number::TagNumber;

///
/// @author Mihael Berčič
/// @date 2. 8. 24
///
#[derive(Clone, Debug)]
pub struct Tag {
    pub vendor: Option<u16>,
    pub profile: Option<u16>,
    pub tag_number: Option<TagNumber>,
}

impl From<Tag> for Vec<u8> {
    fn from(tag: Tag) -> Vec<u8> {
        let mut data = vec![];
        if let Some(vendor) = tag.vendor { data.write_u16::<LittleEndian>(vendor).expect("Unable to write vendor id..."); }
        if let Some(profile) = tag.profile { data.write_u16::<LittleEndian>(profile).expect("Unable to write vendor id..."); }

        if let Some(tag) = tag.tag_number {
            match tag {
                TagNumber::Short(number) => {
                    data.write_byte(number).expect("Unable to write short tag number...");
                }
                TagNumber::Medium(number) => {
                    data.write_u16::<LittleEndian>(number).expect("Unable to write medium tag number...");
                }
                TagNumber::Long(number) => {
                    data.write_u32::<LittleEndian>(number).expect("Unable to write long tag number...");
                }
            }
        }

        data
    }
}

