use crate::session::protocol::interaction::device::Device;
use crate::session::protocol::interaction::endpoint::Endpoint;

///
/// @author Mihael Berčič
/// @date 24. 9. 24
///
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
        let index = self.device.endpoints.len() as u16;
        self.device.endpoints.insert(index, endpoint);
        self
    }

    pub fn build(self) -> Device {
        self.device
    }
}
