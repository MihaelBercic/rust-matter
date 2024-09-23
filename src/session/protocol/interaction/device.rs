use crate::session::protocol::interaction::endpoint::Endpoint;
use crate::session::protocol::interaction::information_blocks::AttributePath;
use crate::tlv::tlv::TLV;
use std::collections::HashMap;

///
/// @author Mihael Berčič
/// @date 22. 9. 24
///
pub struct Device {
    endpoints: HashMap<usize, Endpoint>,
}

impl Device {
    pub fn read_attribute(&self, attribute_path: AttributePath) {
        // if wildcard, get from all
        // if not, get from needed
    }
}

pub struct DeviceBuilder {
    device: Device,
}

impl DeviceBuilder {
    pub fn new() -> DeviceBuilder {
        Self {
            device: Device { endpoints: Default::default() },
        }
    }

    pub fn add_endpoint(mut self, endpoint: Endpoint) -> Self {
        let index = self.device.endpoints.len();
        self.device.endpoints.insert(index, endpoint);
        self
    }

    pub fn build(self) -> Device {
        self.device
    }
}


#[derive(Clone, Debug)]
pub enum QueryParameter<T> {
    Wildcard,
    Specific(T),
}

pub trait ClusterImplementation {
    fn read_attribute(&self, attribute_path: AttributePath) -> TLV;
    // fn write_attribute(attribute_path: AttributePath, value: TLV);
    // fn invoke_command(command_path: CommandPath);
}


pub struct OnOffCluster {
    pub on_off: bool,
}

impl ClusterImplementation for OnOffCluster {
    fn read_attribute(&self, attribute_path: AttributePath) -> TLV {
        todo!()
    }
}