use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::str::FromStr;
use netif;

pub fn hi() {
    let multicast = Ipv6Addr::from_str("ff02::fb:5353").unwrap();
    let udp = UdpSocket::bind("[::]:0").expect("Unable to bind!");
    let interfaces = netif::up().unwrap();
    let en = interfaces.filter(|x| x.name().contains("en")).max_by_key(|x| x.scope_id()).unwrap();

    udp.join_multicast_v6(&multicast, en.scope_id().unwrap()).expect("Unable to join multicast...");
    udp.join_multicast_v4(&Ipv4Addr::from_str("224.0.0.251").unwrap(), &Ipv4Addr::new(0, 0, 0, 0)).expect("TODO: panic message");

    match udp.send_to(b"Hello", format!("FF02::fb%{}:5353", en.name())) { // Trying to send a packet to multicast address...
        Ok(bytes_sent) => println!("Sent {} bytes", bytes_sent),
        Err(err) => eprintln!("Error sending data: {}", err),
    }
    println!("Local: {}", udp.local_addr().unwrap());
    let mut buffer = [0; 65000];
    let (size, sender) = udp.recv_from(&mut buffer).unwrap();
    println!("Received: {} from {} ==> {}", size, sender, String::from_utf8_lossy(&buffer[..size]));
}
