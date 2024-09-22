use crate::tlv::element_type::ElementType;
use crate::tlv::tag_control::TagControl;

///
/// @author Mihael Berčič
/// @date 2. 8. 24
///
#[derive(Clone, Debug)]
pub struct Control {
    pub tag_control: TagControl,
    pub element_type: ElementType,
}

impl Into<u8> for Control {
    fn into(self) -> u8 {
        let mut byte = 0u8;
        byte |= self.tag_control as u8;
        byte <<= 5;
        byte |= Into::<u8>::into(self.element_type);
        byte
    }
}
