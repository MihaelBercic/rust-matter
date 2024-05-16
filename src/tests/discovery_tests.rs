#[cfg(test)]
pub mod discovery_tests {
    use crate::crypto::random_bits;
    use crate::discovery::constants::{ADD_ACCESSORY_PACKET, PROTOCOL};
    use crate::discovery::mdns::records::TXTRecord;
    use crate::discovery::mdns::structs::*;

    #[test]
    fn mdns_packet_decode() {
        // println!("{}", String::from_utf8_lossy(&SAMPLE_PACKET));
        let mdns_packet = MDNSPacket::try_from(&ADD_ACCESSORY_PACKET[..]).expect("Should parse");
        let is_our_protocol = mdns_packet.query_records.iter().any(|q| q.label == PROTOCOL);
        println!("Is our protocol: {}", is_our_protocol);
    }

    #[test]
    fn txt_record_test() {
        let values = format!("A={}\nB={}\nC={}", 1, 2, 33);
        let txt = TXTRecord { text: values };
        let bytes: Vec<u8> = txt.into();
        println!("{}", bytes.iter().map(|x| format!("0x{:x}", x)).collect::<Vec<String>>().join(" "));
        println!("{}", String::from_utf8_lossy(&bytes));
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
