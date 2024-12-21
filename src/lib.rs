use std::{
    net::UdpSocket,
    sync::{mpsc::channel, Arc, Mutex},
};

use mdns::device_information::Details;
use network::{network_message::NetworkMessage, start_listening_thread, start_outgoing_thread};
use rewrite::{
    device::{Device, SharedDevice},
    start_processing_thread,
};

pub mod mdns;
pub mod rewrite;

#[macro_use]
pub(crate) mod logging;
pub(crate) mod constants;
pub(crate) mod crypto;
pub(crate) mod network;
pub(crate) mod tlv;
pub(crate) mod utils;

use logging::*;

// pub(crate) mod test;

pub fn start(interface: mdns::NetworkInterface, device: Device) {
    let Details {
        device_type,
        vendor_id,
        product_id,
        device_name,
        ..
    } = &device.details;
    println!(
        "-------------------------------------------------------------
\t⦿ Device Type \t\t{color_green}{:x?}{color_reset}
\t⦿ Vendor ID \t\t{color_magenta}0x{:x}{color_reset}
\t⦿ Product ID \t\t{color_yellow}0x{:x}{color_reset}
\t⦿ Device Name \t\t{color_blue}{}{color_reset}
-------------------------------------------------------------",
        device_type, vendor_id, product_id, device_name
    );

    let udp_socket = Arc::new(UdpSocket::bind(format!("[::%{}]:0", interface.index)).expect("Unable to bind to tcp..."));
    let (processing_sender, processing_receiver) = channel::<NetworkMessage>();
    let (outgoing_sender, outgoing_receiver) = channel::<NetworkMessage>();

    let shared_device: SharedDevice = Arc::new(Mutex::new(device));
    mdns::start_advertising(&udp_socket, shared_device.clone(), &interface);

    start_listening_thread(processing_sender.clone(), udp_socket.clone(), outgoing_sender.clone());
    start_outgoing_thread(outgoing_receiver, udp_socket);
    start_processing_thread(processing_receiver, outgoing_sender, shared_device.clone())
        .join()
        .expect("Unable to start the thread for processing messages...");
    // TODO: remove join, return channel for cluster modification.
}
