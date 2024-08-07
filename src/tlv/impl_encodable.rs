use crate::tlv::element_type::ElementType;
use crate::tlv::encodable_value::EncodableValue;

///
/// @author Mihael Berčič
/// @date 1. 8. 24
///
impl EncodableValue for bool {
    fn to_bytes(self) -> Vec<u8> {
        let boolean_value = match self {
            true => ElementType::BooleanTrue,
            false => ElementType::BooleanFalse
        };
        let encodable: u8 = boolean_value.into();
        vec![encodable]
    }
}

macro_rules! byte_representable {
    ($($t:ty),* => {$a:item}) => {
        $(
        impl EncodableValue for $t {
            $a
        }
        )*
    };
}

byte_representable! {
    i8,i16,i32,i64,i128,u8,u16,u32,u64,u128, f32, f64 => {
        fn to_bytes(self) -> Vec<u8> {
            self.to_le_bytes().to_vec()
        }
    }
}