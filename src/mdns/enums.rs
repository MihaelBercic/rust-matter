#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum CommissionState {
    NotCommissioned = 2,
    InCommissioning = 1,
    Commissioned = 0,
}

#[repr(u16)]
#[derive(Copy, Clone)]
pub enum DeviceType {
    Light = 0x0100,
    DimmableLight = 0x0101,
    Thermostat = 0x0301,
    DoorLock = 0x000A,
}
