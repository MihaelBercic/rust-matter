use crate::log_info;
use crate::session::protocol::interaction::cluster::network_info::NetworkInfo;
use crate::session::protocol::interaction::cluster::{ClusterImplementation, NetworkCommissioningStatus};
use crate::session::protocol::interaction::enums::QueryParameter;
use crate::session::protocol::interaction::information_blocks::attribute::report::AttributeReport;
use crate::session::protocol::interaction::information_blocks::attribute::Attribute;
use crate::session::protocol::interaction::information_blocks::{AttributePath, CommandData, InvokeResponse};
use std::any::Any;

///
/// @author Mihael Berčič
/// @date 8. 10. 24
///

pub struct NetworkCommissioningCluster {
    max_networks: Attribute<u8>,
    networks: Attribute<Vec<NetworkInfo>>,
    scan_max_seconds: Attribute<u8>,
    connect_max_seconds: Attribute<u8>,
    interface_enabled: Attribute<bool>,
    last_networking_status: Attribute<NetworkCommissioningStatus>,
    last_network_id: Attribute<Vec<u8>>,
    last_connect_error: Attribute<i32>,
}

impl NetworkCommissioningCluster {
    pub fn new() -> Self {
        Self {
            max_networks: Attribute { id: 0x0000, value: 1 },
            networks: Attribute { id: 0x0001, value: vec![] },
            scan_max_seconds: Attribute { id: 0x0002, value: 60 },
            connect_max_seconds: Attribute { id: 0x0003, value: 60 },
            interface_enabled: Attribute { id: 0, value: true },
            last_networking_status: Attribute { id: 0, value: NetworkCommissioningStatus::Success },
            last_network_id: Attribute { id: 0, value: vec![12, 12, 3, 120, 0, 03, 0, 01, 20, 3] },
            last_connect_error: Attribute { id: 0, value: 0 },
        }
    }

    pub fn connect(&self) {
        log_info!("Connect function called!")
    }
}

impl ClusterImplementation for NetworkCommissioningCluster {
    fn read_attributes(&self, attribute_path: AttributePath) -> Vec<AttributeReport> {
        match attribute_path.attribute_id {
            QueryParameter::Wildcard => {
                vec![
                    self.max_networks.clone().into(),
                    self.networks.clone().into(),
                    self.scan_max_seconds.clone().into(),
                    self.connect_max_seconds.clone().into(),
                    self.interface_enabled.clone().into(),
                    self.last_networking_status.clone().into(),
                    self.last_network_id.clone().into(),
                    self.last_connect_error.clone().into(),
                ]
            }
            QueryParameter::Specific(attribute_id) => {
                vec![match attribute_id {
                    0x0000 => self.max_networks.clone().into(),
                    0x0001 => self.networks.clone().into(),
                    0x0002 => self.scan_max_seconds.clone().into(),
                    0x0003 => self.connect_max_seconds.clone().into(),
                    0x0004 => self.interface_enabled.clone().into(),
                    0x0005 => self.last_networking_status.clone().into(),
                    0x0006 => self.last_network_id.clone().into(),
                    0x0007 => self.last_connect_error.clone().into(),
                    _ => Attribute { id: 65532, value: 1 }.into()
                }]
            }
        }
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }

    fn invoke_command(&mut self, command: CommandData) -> Vec<InvokeResponse> {
        todo!()
    }
}

