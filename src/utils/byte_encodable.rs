///
/// @author Mihael Berčič
/// @date 28. 7. 24
///
pub trait ByteEncodable {
    fn from_bytes(bytes: &[u8]) -> Self;
    fn to_bytes(&self) -> Vec<u8>;
}