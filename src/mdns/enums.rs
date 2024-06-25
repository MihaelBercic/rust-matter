#[repr(u8)]
#[derive(Copy, Clone)]
pub enum CommissionState {
    NotCommissioned = 2,
    Commissioned = 0,
}

#[repr(u16)]
#[derive(Copy, Clone)]
pub enum DeviceType {
    Thermostat = 301
}
