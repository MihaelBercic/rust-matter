#![allow(unused)]

use crate::utils::MatterError;

///
/// @author Mihael Berčič
/// @date 28. 7. 24
///
pub trait ByteEncodable {
    /// Returns a representation of [Self] from [bytes];
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, MatterError>
        where Self: Sized;
}