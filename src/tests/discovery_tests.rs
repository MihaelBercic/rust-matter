#[cfg(test)]
pub mod discovery_tests {
    use crate::constants::PROTOCOL;
    use crate::crypto::random_bits;
    use crate::mdns::packet::MDNSPacket;
    use crate::tests::constants::ADD_ACCESSORY_PACKET;
    use crate::utils::bit_subset::BitSubset;

    #[test]
    fn mdns_packet_decode() {
        // println!("{}", String::from_utf8_lossy(&SAMPLE_PACKET));
        let mdns_packet = MDNSPacket::try_from(&ADD_ACCESSORY_PACKET[..]).expect("Should parse");
        let is_our_protocol = mdns_packet.query_records.iter().any(|q| q.label == PROTOCOL);
        println!("Is our protocol: {}", is_our_protocol);
    }

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
        println!("BE: {} LE: {} => {}", number_be, number_le, bits.iter().map(|x| format!("{:08b}", x)).collect::<Vec<String>>().join(" "));
    }
}
