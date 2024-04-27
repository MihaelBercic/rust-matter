#![allow(unused)]

pub const MDNS_PORT: u16 = 5353;
pub const LOCAL_DOMAIN: &str = ".local";
pub const IPV6_MULTICAST_ADDRESS: &str = "FF02::FB";

pub const SAMPLE_PACKET: [u8; 285] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x04, 0x5f, 0x68, 0x61,
    0x70, 0x04, 0x5f, 0x75, 0x64, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x0c, 0x00,
    0x01, 0x0f, 0x5f, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x6e, 0x69, 0x6f, 0x6e, 0x2d, 0x6c, 0x69, 0x6e,
    0x6b, 0x04, 0x5f, 0x74, 0x63, 0x70, 0xc0, 0x16, 0x00, 0x0c, 0x00, 0x01, 0x07, 0x5f, 0x72, 0x64,
    0x6c, 0x69, 0x6e, 0x6b, 0xc0, 0x31, 0x00, 0x0c, 0x00, 0x01, 0x0c, 0x5f, 0x73, 0x6c, 0x65, 0x65,
    0x70, 0x2d, 0x70, 0x72, 0x6f, 0x78, 0x79, 0xc0, 0x11, 0x00, 0x0c, 0x00, 0x01, 0xc0, 0x21, 0x00,
    0x0c, 0x00, 0x01, 0x00, 0x00, 0x11, 0x88, 0x00, 0x10, 0x0d, 0x4d, 0x69, 0x68, 0x61, 0xe2, 0x80,
    0x99, 0x73, 0x20, 0x52, 0x6f, 0x6f, 0x6d, 0xc0, 0x21, 0xc0, 0x21, 0x00, 0x0c, 0x00, 0x01, 0x00,
    0x00, 0x11, 0x88, 0x00, 0x0e, 0x0b, 0x4c, 0x69, 0x76, 0x69, 0x6e, 0x67, 0x20, 0x52, 0x6f, 0x6f,
    0x6d, 0xc0, 0x21, 0xc0, 0x21, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x11, 0x88, 0x00, 0x07, 0x04,
    0x69, 0x50, 0x61, 0x64, 0xc0, 0x21, 0xc0, 0x21, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x11, 0x88,
    0x00, 0x19, 0x16, 0x4d, 0x69, 0x68, 0x61, 0x65, 0x6c, 0xe2, 0x80, 0x99, 0x73, 0x20, 0x4d, 0x61,
    0x63, 0x42, 0x6f, 0x6f, 0x6b, 0x20, 0x50, 0x72, 0x6f, 0xc0, 0x21, 0xc0, 0x4a, 0x00, 0x0c, 0x00,
    0x01, 0x00, 0x00, 0x11, 0x88, 0x00, 0x1e, 0x1b, 0x37, 0x30, 0x2d, 0x33, 0x35, 0x2d, 0x36, 0x30,
    0x2d, 0x36, 0x33, 0x2e, 0x31, 0x20, 0x4d, 0x69, 0x68, 0x61, 0xe2, 0x80, 0x99, 0x73, 0x20, 0x52,
    0x6f, 0x6f, 0x6d, 0xc0, 0x4a, 0xc0, 0x4a, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x11, 0x88, 0x00,
    0x1c, 0x19, 0x37, 0x30, 0x2d, 0x33, 0x35, 0x2d, 0x36, 0x30, 0x2d, 0x36, 0x33, 0x2e, 0x31, 0x20,
    0x4c, 0x69, 0x76, 0x69, 0x6e, 0x67, 0x20, 0x52, 0x6f, 0x6f, 0x6d, 0xc0, 0x4a,
];
