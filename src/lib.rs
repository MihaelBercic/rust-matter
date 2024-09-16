#![allow(unused)]
#![allow(dead_code)]

use crate::logging::{color_blue, color_red, color_reset};
use crate::mdns::mdns_device_information::MDNSDeviceInformation;
use crate::network::network_message::NetworkMessage;
use crate::network::{start_listening_thread, start_outgoing_thread};
use crate::secure::enums::MatterDestinationID;
use crate::secure::enums::MatterDestinationID::Group;
use crate::secure::message::MatterMessage;
use crate::secure::message_builder::MatterMessageBuilder;
use crate::secure::protocol::communication::counters::{increase_counter, GLOBAL_UNENCRYPTED_COUNTER};
use crate::secure::protocol::enums::ProtocolOpcode::{MRPStandaloneAcknowledgement, StatusReport};
use crate::secure::protocol::enums::{GeneralCode, ProtocolCode, ProtocolOpcode};
use crate::secure::protocol::message::ProtocolMessage;
use crate::secure::protocol::message_builder::ProtocolMessageBuilder;
use crate::secure::protocol::protocol_id::ProtocolID;
use crate::secure::session::{Exchange, UnencryptedSession};
use crate::secure::{process_unencrypted, start_processing_thread};
use crate::utils::MatterError;
use crate::utils::MatterLayer::Transport;
use byteorder::WriteBytesExt;
use p256::elliptic_curve::group::GroupEncoding;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use std::collections::HashMap;
use std::net::UdpSocket;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::SystemTime;
use tlv::structs::status_report;

pub(crate) mod tests;
pub(crate) mod crypto;
pub mod mdns;
pub(crate) mod utils;
pub(crate) mod secure;
pub(crate) mod network;
pub(crate) mod tlv;
pub mod logging;

pub static START_TIME: LazyLock<SystemTime> = LazyLock::new(SystemTime::now);


pub static UNENCRYPTED_SESSIONS: LazyLock<Mutex<HashMap<u16, UnencryptedSession>>> = LazyLock::new(|| Default::default());

fn process_message(network_message: NetworkMessage, outgoing_sender: &Sender<NetworkMessage>, exchange_map: &mut HashMap<u16, Exchange>) -> Result<(), MatterError> {
    let matter_message = network_message.message;

    // TODO: If secure, protocol message is encoded. Gotta find another way...
    let protocol_message = ProtocolMessage::try_from(&matter_message.payload[..])?;
    log_info!("{color_red}[{:?}]{color_blue}[{:?}]{color_reset} message received.", protocol_message.protocol_id, protocol_message.opcode);
    match protocol_message.opcode {
        StatusReport => {
            let status_report = status_report::StatusReport::try_from(protocol_message);
            let representation = format!("{:?}", status_report);
            return Err(MatterError::Custom(Transport, representation));
        }
        MRPStandaloneAcknowledgement => {
            // TODO: Remove from retransmission...
            return Ok(());
        }
        _ => {}
    }
    log_info!("Continuing on... {color_red}[{:?}]{color_blue}[{:?}]{color_reset} message received.", protocol_message.protocol_id, protocol_message.opcode);
    if matter_message.header.is_unsecured_unicast_session() {
        let session_map = &mut UNENCRYPTED_SESSIONS.lock();
        if let Ok(session_map) = session_map {
            let existing = session_map.entry(matter_message.header.session_id).or_insert(Default::default());
            let mut response = process_unencrypted(existing, matter_message, protocol_message)?;
            response.address = network_message.address;
            outgoing_sender.send(response);
        }
    } else {
        // Process secured
    }

    /*
    ✅ validity_checks(...);
    obtain_keys(...)
    if keys {
       process_privacy(...)
       process_security(...)
    }
    process_counter(...);
    process_reliability(...);
    if unicast {
       set_session_timestamp
       set_active_timestamp
    }

    // Move to Exchange Message Processing
    */
    Ok(())
}


/// Starts the matter protocol advertisement (if needed) and starts running the matter protocol based on the settings provided.
pub fn start(device_info: MDNSDeviceInformation, interface: NetworkInterface) {
    let udp_socket = Arc::new(UdpSocket::bind(format!("[::%{}]:0", interface.index)).expect("Unable to bind to tcp..."));
    let (processing_sender, processing_receiver) = channel::<NetworkMessage>();
    let (outgoing_sender, outgoing_receiver) = channel::<NetworkMessage>();

    mdns::start_advertising(&udp_socket, device_info, &interface);
    log_debug!("Starting listening thread...");
    start_listening_thread(processing_sender.clone(), udp_socket.clone());
    log_debug!("Starting outgoing thread...");
    start_outgoing_thread(outgoing_receiver, udp_socket);
    log_debug!("Starting processing thread...");
    start_processing_thread(processing_receiver, outgoing_sender).join().expect("Unable to start the thread for processing messages...");
}

fn perform_validity_checks(message: &MatterMessage) -> bool {
    let header = &message.header;
    let unicast_check = header.is_secure_unicast_session() && matches!(header.destination_node_id, Some(Group(_)));
    let path_check = header.destination_node_id.is_none() || header.source_node_id.is_none();
    let group_check = header.is_group_session() && path_check;

    if header.flags.version() != 0
        || unicast_check
        || group_check {
        return false;
    }
    true
}

fn build_simple_response(opcode: ProtocolOpcode, exchange_id: u16, matter_message: &MatterMessage, payload: &[u8]) -> NetworkMessage {
    let protocol = ProtocolMessageBuilder::new()
        .set_needs_acknowledgement(true)
        .set_exchange_id(exchange_id)
        .set_opcode(opcode)
        .set_payload(payload)
        .set_acknowledged_message_counter(matter_message.header.message_counter)
        .build();
    let matter = MatterMessageBuilder::new()
        .set_destination(MatterDestinationID::Node(matter_message.header.source_node_id.unwrap()))
        .set_counter(increase_counter(&GLOBAL_UNENCRYPTED_COUNTER))
        .set_payload(&protocol.to_bytes())
        .build();
    NetworkMessage {
        address: None,
        message: matter,
        retry_counter: 0,
    }
}

fn build_status_response(general_code: GeneralCode, protocol_id: ProtocolID, protocol_code: ProtocolCode, exchange_id: u16, matter_message: &MatterMessage) -> NetworkMessage {
    let status_report = status_report::StatusReport {
        general_code,
        protocol_id: protocol_id.clone(),
        protocol_code,
        data: vec![],
    }.to_bytes();
    let protocol = ProtocolMessageBuilder::new()
        .set_needs_acknowledgement(true)
        .set_exchange_id(exchange_id)
        .set_opcode(StatusReport)
        .set_payload(&status_report)
        .set_protocol(protocol_id)
        .set_acknowledged_message_counter(matter_message.header.message_counter)
        .build();
    let matter = MatterMessageBuilder::new()
        .set_destination(MatterDestinationID::Node(matter_message.header.source_node_id.unwrap()))
        .set_counter(increase_counter(&GLOBAL_UNENCRYPTED_COUNTER))
        .set_payload(&protocol.to_bytes())
        .build();
    NetworkMessage {
        address: None,
        message: matter,
        retry_counter: 0,
    }
}

pub struct NetworkInterface {
    pub index: u32,
    pub do_custom: bool,
}