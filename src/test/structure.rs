use crate::session::protocol::interaction::information_blocks::attribute::Attribute;
use crate::{log_error, log_info};
use std::any::Any;
use std::collections::HashMap;

///
/// @author Mihael Berčič
/// @date 1. 10. 24
///
trait SampleTrait: Any {
    fn read(&self);
    fn as_any(&mut self) -> &mut dyn Any;
}

fn compute_key(endpoint_id: u8, cluster_id: u8) -> u16 {
    let mut key = endpoint_id as u16;
    key << 8;
    key |= cluster_id as u16;
    key
}

#[derive(Debug)]
struct MyCluster {
    is_on: Attribute<bool>,
}

#[derive(Debug)]
struct SecondCluster {
    is_on: Attribute<bool>,
}

impl SampleTrait for MyCluster {
    fn read(&self) { log_info!("Reading attributes!") }

    fn as_any(&mut self) -> &mut dyn Any { self }
}

impl SampleTrait for SecondCluster {
    fn read(&self) { log_info!("Reading attributes!") }

    fn as_any(&mut self) -> &mut dyn Any { self }
}

struct Device {
    clusters: HashMap<u16, Box<dyn SampleTrait>>,
}

impl Device {
    fn insert<T: SampleTrait>(&mut self, endpoint_id: u8, id: u8, val: T) {
        self.clusters.insert(compute_key(endpoint_id, id), Box::new(val));
    }

    fn get<T: SampleTrait>(&mut self, endpoint_id: u8, id: u8) -> Option<&mut T> {
        self.clusters.get_mut(&compute_key(endpoint_id, id)).map(|v| v.as_any().downcast_mut())?
    }
}

#[test]
fn test() {
    let my_cluster = MyCluster { is_on: Attribute { id: 0, value: false } };
    dbg!(&my_cluster);
    let mut device = Device { clusters: HashMap::new() };
    device.insert(0, 1, my_cluster);
    // down the line

    if let Some(gotta_change) = device.get::<SecondCluster>(0, 1) {
        gotta_change.is_on.value = true;
    } else { log_error!("We got None") }

    if let Some(gotta_change) = device.get::<MyCluster>(0, 1) {
        dbg!(&gotta_change.is_on);
    } else { log_error!("We got None") }

    for cluster in device.clusters.values() {
        cluster.read();
    }
}
