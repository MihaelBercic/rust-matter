#[derive(Eq, PartialEq, Debug)]
pub struct ProtocolSecuredExtensions {
    pub data_length: u16,
    pub data: Vec<u8>,
}