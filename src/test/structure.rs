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

struct Device {
    clusters: HashMap<u16, Box<dyn SampleTrait>>,
}
fn compute_key(i: u8, u: u8) -> u16 { 0 }

impl Device {
    fn insert<T: SampleTrait>(&mut self, endpoint_id: u8, id: u8, val: T) {
        self.clusters.insert(compute_key(endpoint_id, id), Box::new(val));
    }

    fn get<T: SampleTrait>(&mut self, endpoint_id: u8, id: u8) -> Option<&mut T> {
        self.clusters.get_mut(&compute_key(endpoint_id, id)).map(|v| v.as_any().downcast_mut())?
    }
}
