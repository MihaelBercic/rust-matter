#[cfg(test)]
pub mod discovery_tests {
    use crate::crypto::random_bits;
    use crate::log_info;

    use crate::mdns::packet::MDNSPacket;
    use crate::test::constants::ADD_ACCESSORY_PACKET;
    use crate::utils::BitSubset;

    #[test]
    fn bit_subset() {
        let num = 0xFF; // 1111 1111 = 255
        let desired = 0xF; // 1111 = 15;
        assert_eq!(num.bit_subset(4, 4), desired);
    }

    #[test]
    fn random_bits_to_int() {
        let bits = random_bits(28);
        let mut array = [0u8; 4];
        array.copy_from_slice(&bits);
        let number_be = u32::from_be_bytes(array);
        let number_le = u32::from_le_bytes(array);
    }
}
