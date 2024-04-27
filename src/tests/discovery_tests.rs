#[cfg(test)]
pub mod discovery_tests {
    use crate::discovery::constants::SAMPLE_PACKET;
    use crate::discovery::mdns::mdns_structs::{BitSubset, MDNSPacket};

    #[test]
    fn hello() {
        let mdns_packet = MDNSPacket::from(&SAMPLE_PACKET);
    }

    #[test]
    fn bit_subset() {
        let num = 0xFF; // 1111 1111 = 255
        let desired = 0xF; // 1111 = 15;
        assert_eq!(num.bit_subset(4, 4), desired);
    }
}
