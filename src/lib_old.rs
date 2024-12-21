// #![allow(unused)]
// #![allow(dead_code)]

// // use crate::network::network_message::NetworkMessage;
// // use crate::network::{start_listening_thread, start_outgoing_thread};
// // use crate::session::counters::increase_counter;
// // use crate::session::matter::builder::MatterMessageBuilder;
// // use crate::session::matter::enums::MatterDestinationID;
// // use crate::session::matter::enums::MatterDestinationID::Group;
// // use crate::session::matter_message::MatterMessage;
// // use crate::session::protocol::interaction::cluster::ClusterImplementation;
// // use crate::session::protocol_message::ProtocolMessage;
// // use crate::session::session::Session;
// // use crate::session::start_processing_thread;
// use byteorder::WriteBytesExt;
// // use crypto::random_bits;
// use p256::elliptic_curve::group::GroupEncoding;
// use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
// // use session::Device;
// use std::collections::HashMap;
// use std::net::UdpSocket;
// use std::sync::atomic::AtomicU32;
// use std::sync::mpsc::channel;
// use std::sync::{Arc, LazyLock, Mutex};
// use std::time::SystemTime;
// use verhoeff::VerhoeffMut;

// // pub mod constants;
// // pub mod crypto;
// // pub mod logging;
// // pub mod mdns;
// // pub mod network;
// // pub mod session;
// pub mod test;
// pub mod tlv;
// pub mod utils;

// pub mod rewrite;

// pub static START_TIME: LazyLock<SystemTime> = LazyLock::new(SystemTime::now);
// pub static SESSIONS: LazyLock<Mutex<HashMap<u16, Session>>> = LazyLock::new(Mutex::default);

// pub type SharedDevice = Arc<Mutex<Device>>;

// /// Starts the matter protocol advertisement (if needed) and starts running the matter protocol based on the settings provided.
// pub fn start(interface: NetworkInterface, device: Device) {
//     let udp_socket = Arc::new(UdpSocket::bind(format!("[::%{}]:0", interface.index)).expect("Unable to bind to tcp..."));
//     let (processing_sender, processing_receiver) = channel::<NetworkMessage>();
//     let (outgoing_sender, outgoing_receiver) = channel::<NetworkMessage>();

//     let shared_device: SharedDevice = Arc::new(Mutex::new(device));
//     mdns::start_advertising(&udp_socket, shared_device.clone(), &interface);

//     start_listening_thread(processing_sender.clone(), udp_socket.clone(), outgoing_sender.clone());
//     start_outgoing_thread(outgoing_receiver, udp_socket);
//     start_processing_thread(processing_receiver, outgoing_sender, shared_device.clone())
//         .join()
//         .expect("Unable to start the thread for processing messages...");
//     // TODO: remove join, return channel for cluster modification.
// }

// fn perform_validity_checks(message: &MatterMessage) -> bool {
//     let header = &message.header;
//     let unicast_check = header.is_secure_unicast_session() && matches!(header.destination_node_id, Some(Group(_)));
//     let path_check = header.destination_node_id.is_none() || header.source_node_id.is_none();
//     let group_check = header.is_group_session() && path_check;

//     if header.flags.version() != 0 || unicast_check || group_check {
//         return false;
//     }
//     true
// }

// fn start_modifying_thread(device_arc: Arc<Mutex<Device>>) {
//     // TODO: Start a modification thread...
// }

// /// Builds a [NetworkMessage] and [MatterMessage] based on [ProtocolMessage] provided.
// fn build_network_message(protocol_message: ProtocolMessage, counter: &AtomicU32, destination: MatterDestinationID) -> NetworkMessage {
//     let matter = MatterMessageBuilder::new()
//         .set_destination(destination)
//         .set_counter(increase_counter(counter))
//         .set_payload(&protocol_message.to_bytes())
//         .build();
//     todo!("...")
// }

// /// TODO: This is a temporary structure, defined for testing.
