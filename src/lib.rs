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
use crate::secure::protocol::message::ProtocolMessage;
use crate::secure::session::{Session, UnencryptedSession};
use crate::secure::{process_unencrypted, start_processing_thread};
use crate::utils::MatterLayer::{Generic, Transport};
use crate::utils::{generic_error, MatterError};
use byteorder::WriteBytesExt;
use p256::elliptic_curve::group::GroupEncoding;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use std::collections::HashMap;
use std::net::UdpSocket;
use std::sync::atomic::AtomicU32;
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


pub static UNENCRYPTED_SESSIONS: LazyLock<Mutex<HashMap<u16, UnencryptedSession>>> = LazyLock::new(Mutex::default);
pub static ENCRYPTED_SESSIONS: LazyLock<Mutex<HashMap<u16, Session>>> = LazyLock::new(Mutex::default);

fn process_message(network_message: NetworkMessage, outgoing_sender: &Sender<NetworkMessage>) -> Result<(), MatterError> {
    let matter_message = network_message.message;
    if matter_message.header.is_insecure_unicast_session() {
        let protocol_message = ProtocolMessage::try_from(&matter_message.payload[..])?;
        log_info!("[Insecure]{color_red}[{:?}]{color_blue}[{:?}]{color_reset} message received.", protocol_message.protocol_id, protocol_message.opcode);

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
        let mut response = process_unencrypted(matter_message, protocol_message)?;
        response.address = network_message.address;
        outgoing_sender.send(response);
    } else {
        let Ok(session_map) = &mut ENCRYPTED_SESSIONS.lock() else {
            return Err(MatterError::Custom(Generic, "PeePoo".to_string()))
        };
        println!("{:?}", session_map);
        let Some(session) = session_map.get_mut(&matter_message.header.session_id) else {
            return Err(generic_error("No session found"));
        };

        log_info!("Working with a session {:?}", session);
        log_error!("We do not know how to process a secured session yet!");
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
    start_listening_thread(processing_sender.clone(), udp_socket.clone());
    start_outgoing_thread(outgoing_receiver, udp_socket);
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

/// Builds a [NetworkMessage] and [MatterMessage] based on [ProtocolMessage] provided.
fn build_network_message(protocol_message: ProtocolMessage, counter: &AtomicU32, destination: MatterDestinationID) -> NetworkMessage {
    let matter = MatterMessageBuilder::new()
        .set_destination(destination)
        .set_counter(increase_counter(&GLOBAL_UNENCRYPTED_COUNTER))
        .set_payload(&protocol_message.to_bytes())
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