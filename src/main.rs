#![allow(unused)]
#![allow(dead_code)]

use std::sync::Mutex;

use matter::secure::enums::MatterDeviceState;

const CURRENT_STATE: Mutex<MatterDeviceState> = Mutex::new(MatterDeviceState::Uncommissioned);

fn main() {
    matter::start()
}