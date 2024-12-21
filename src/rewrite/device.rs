use verhoeff::VerhoeffMut;

use super::session::{
    interaction_model::{cluster_implementation::ClusterImplementation, enums::ClusterID},
    Session,
};
use crate::{crypto::random_bits, log_info, mdns::device_information::Details};
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex},
    time::SystemTime,
};

pub type Cluster = dyn ClusterImplementation + Send;
pub type Endpoint = HashMap<u32, Box<Cluster>>;
pub type SharedDevice = Arc<Mutex<Device>>;

pub static START_TIME: LazyLock<SystemTime> = LazyLock::new(SystemTime::now);
pub static SESSIONS: LazyLock<Mutex<HashMap<u16, Session>>> = LazyLock::new(Mutex::default);

pub struct Device {
    pub endpoints_map: HashMap<u16, Endpoint>,
    pub details: Details,
}

impl Device {
    pub fn new(details: Details) -> Self {
        Self {
            endpoints_map: Default::default(),
            details,
        }
    }

    fn get<T: ClusterImplementation>(&mut self, endpoint_id: u16, cluster_id: ClusterID) -> Option<&mut T> {
        self.endpoints_map
            .get_mut(&endpoint_id)
            .map(|cluster_map| cluster_map.get_mut(&(cluster_id as u32)).map(|cluster| cluster.as_any().downcast_mut())?)?
    }
}

pub fn compute_pairing_code(device: &Device) {
    let device = &device.details;
    let passcode: [u8; 4] = random_bits(27).try_into().unwrap();
    let passcode = u32::from_be_bytes(passcode.clone());

    let passcode = 20202021;
    let mut pairing_code = if false {
        // if use custom flow
        format!(
            "{}{:0>5}{:0>4}{:0>5}{:0>5}",
            1 << 2 | device.discriminator >> 10,
            ((device.discriminator as u32 & 0x300) << 6) | (passcode & 0x3FFF),
            passcode >> 14,
            device.vendor_id,
            device.product_id
        )
    } else {
        format!(
            "{}{:0>5}{:0>4}",
            0 << 2 | device.discriminator >> 10,
            ((device.discriminator as u32 & 0x300) << 6) | (passcode & 0x3FFF),
            passcode >> 14
        )
    };
    pairing_code.push_verhoeff_check_digit();
    log_info!("Pairing code: {}", pairing_code);
}
