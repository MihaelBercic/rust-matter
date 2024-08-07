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

impl Into<Vec<u8>> for Tag {
    fn into(self) -> Vec<u8> {
        let mut data = vec![];
        if let Some(vendor) = self.vendor { data.write_u16::<LittleEndian>(vendor).expect("Unable to write vendor id..."); }
        if let Some(profile) = self.profile { data.write_u16::<LittleEndian>(profile).expect("Unable to write vendor id..."); }

        if let Some(tag) = self.tag_number {
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

