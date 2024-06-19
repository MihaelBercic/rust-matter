use std::collections::HashMap;

use crate::discovery::mdns::structs::BitSubset;
use crate::Matter;
use crate::service::protocol::communication::exhange::Exchange;
use crate::service::protocol::structs::ProtocolMessageBuilder;
use crate::service::structs::MatterMessage;
use crate::tests::constants::FIRST_PACKET_SAMPLE;
use crate::transport::Transport;

#[test]
fn matter_setup() {
    let matter = Matter::new();
    match matter.receive(&FIRST_PACKET_SAMPLE[..]) {
        Ok(_) => {}
        Err(error) => { panic!("Yeah error... {}", error) }
    };
    // let matter_service = MatterService::new();
    // matter_service.process(matter_message);
}

#[test]
fn protocol_message_builder() {
    let message = ProtocolMessageBuilder::new()
        .set_opcode(10)
        .build();
    assert_eq!(message.opcode, 10);
}

#[test]
fn set_bits() {
    let mut x = 1u8;
    x = x.set_bits(0..=2, 0b11);
    assert_eq!(x, 0b0000_0011);
    x = x.set_bits(0..=1, 0b0);
    assert_eq!(x, 0b0000_0000);
    x = x.set_bits(3..=7, 0b10101);
    assert_eq!(x, 0b1010_1000);
    assert_eq!(0b1111_1111u8.set_bits(0..=4, 0b00110), 0b1110_0110);
    assert_eq!(0b1111_1111u8.set_bits(0..=0, 0), 0b1111_1110);
    assert_eq!(0u8.set_bits(3..=3, 1), 0b0000_1000);
    assert_eq!(0u8.set_bits(3..=5, 0b111), 0b0011_1000);
}

pub struct ExchangeManager {
    pub exchanges: HashMap<u16, Exchange>,
}

pub struct TransportLayerr {
    incoming_queue: Vec<MatterMessage>,
    outgoing_queue: Vec<MatterMessage>,
}
