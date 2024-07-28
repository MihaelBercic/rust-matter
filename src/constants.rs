/// ======= Protocol =======
pub const PROTOCOL_ID_SECURE_CHANNEL: u16 = 0x0000;
pub const PROTOCOL_ID_INTERACTION_MODEL: u16 = 0x0001;
pub const PROTOCOL_ID_BDX: u16 = 0x0002;
pub const PROTOCOL_ID_USER_DIRECTED_COMMISSIONING: u16 = 0x0003;
pub const PROTOCOL_ID_FOR_TESTING: u16 = 0x0004;


/// ======= MDNS =======
pub const MDNS_PORT: u16 = 5353;
pub const LOCAL_DOMAIN: &str = ".local";
pub const PROTOCOL: &str = "_matterc._udp.local";
pub const IPV6_MULTICAST_ADDRESS: &str = "FF02::FB";