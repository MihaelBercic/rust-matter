use crate::discovery::constants::MDNS_PORT;
use crate::discovery::mdns::mdns_structs::MDNSPacket;
use crate::discovery::mdns::multicast_socket::MulticastSocket;

mod discovery;
mod useful;

fn main() {
    let interface = netif::up().unwrap().find(|x| x.name() == "en7").unwrap();
    let mut socket = MulticastSocket::new(interface, MDNS_PORT);

    let (size, _) = socket.receive_from().unwrap();
    let data = &socket.buffer[0..size];
    let code = data
        .iter()
        .map(|x| format!("{:#04x}", x))
        .collect::<Vec<String>>()
        .join(",");
    let sample = String::from_utf8_lossy(data);
    let _ = MDNSPacket::from(data);
    println!("{}", sample);
    println!(": [u8;{}] = [{}]", size, code)
}
