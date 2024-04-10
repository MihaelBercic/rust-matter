use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::str::FromStr;

pub fn hi() {
    let local = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 61666, 0, 0);
    let udp = UdpSocket::bind(&local).expect("Unable to bind!");
    match udp.send_to(b"Hello", "[ff02::fb]:5353") { // Trying to send a packet to multicast address...
        Ok(bytes_sent) => println!("Sent {} bytes", bytes_sent),
        Err(err) => eprintln!("Error sending data: {}", err),
    }


    let multicast = Ipv6Addr::from_str("ff02::fb").unwrap();
    println!("Local: {}", udp.local_addr().unwrap());
    // let mut buffer = [0; 65000];
    // let (size, sender) = udp.recv_from(&mut buffer).unwrap();
    // println!("Received: {} from {} ==> {}", size, sender, String::from_utf8_lossy(&buffer[..size]));
}
