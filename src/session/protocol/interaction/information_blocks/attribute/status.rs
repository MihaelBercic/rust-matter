use crate::session::protocol::interaction::information_blocks::AttributePath;

///
/// @author Mihael Berčič
/// @date 27. 9. 24
///
#[derive(Debug)]
pub struct AttributeStatus {
    pub path: AttributePath,
    pub status: Status,
}

#[derive(Debug)]
pub struct Status {
    pub status: u8,
    pub cluster_status: u8,
}