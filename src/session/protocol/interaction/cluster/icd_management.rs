use crate::session::protocol::interaction::information_blocks::attribute::Attribute;

///
/// @author Mihael Berčič
/// @date 13. 10. 24
///
pub struct IcdManagement {
    pub idle_mode_interval: Attribute<u32>,
    pub active_mode_interval: Attribute<u32>,
    pub active_mode_threshold: Attribute<u16>,
    pub registered_clients: Attribute<Vec<MonitoringRegistration>>,
    pub icd_counter: Attribute<u32>,
    pub clients_supported_per_fabric: Attribute<u16>,
}

pub struct MonitoringRegistration {
    check_in_node_id: u64,
    monitored_subject: u32,
    key: [u8; 16],
}