pub trait EncodableValue {
    fn to_bytes(self) -> Vec<u8>;
}