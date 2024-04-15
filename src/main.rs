use std::ffi::c_void;
use std::mem::size_of;
use std::net::{Ipv6Addr, UdpSocket};
use std::os::fd::FromRawFd;
use std::str::FromStr;

use libc::{AF_INET6, bind, c_char, in6_addr, in_addr, perror, setsockopt, SO_REUSEADDR, SO_REUSEPORT, SOCK_DGRAM, sockaddr, sockaddr_in, sockaddr_in6, socket, socklen_t, SOL_SOCKET};

fn main() {
    let error_text = "OPT FAILED" as *const _;
    let multicast_ipv6 = Ipv6Addr::from_str("ff02::fb").unwrap();
    let fd = unsafe { socket(AF_INET6, SOCK_DGRAM, 0) };
    let option_value = 1;
    let cc = &option_value as *const _;

    unsafe {
        let x = &sockaddr_in6 {
            sin6_family: 30, // AF_INET6
            sin6_port: 5353u16.to_be(),
            sin6_addr: in6_addr { s6_addr: [0u8; 16] },
            sin6_len: 0,
            sin6_flowinfo: 0,
            sin6_scope_id: 0,
        } as *const _ as *const sockaddr;

        // Set the SO_REUSEADDR option
        if setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, cc as *const c_void, size_of::<i32>() as socklen_t) < 0 {
            perror(error_text as *const c_char);
        }

        // Set the SO_REUSEPORT option
        if setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, cc as *const c_void, size_of::<i32>() as socklen_t) < 0 {
            perror(error_text as *const c_char);
        }

        if bind(fd, x, size_of::<sockaddr_in6>() as socklen_t) < 0 {
            perror(error_text as *const c_char);
        }
    }
    let mut socket = unsafe { UdpSocket::from_raw_fd(fd) };
    let interface = netif::up().unwrap().filter(|x| x.name().contains("en7")).max_by(|x, y| x.scope_id().cmp(&y.scope_id())).unwrap();
    socket.join_multicast_v6(&multicast_ipv6, interface.scope_id().unwrap()).expect("Unable to join...");

    // Receive packets!
    let mut buffer = [0u8; 1000];
    loop {
        let (size, addr) = socket.recv_from(&mut buffer).unwrap();
        println!("Size: {} => {}", size, String::from_utf8_lossy(&buffer[..size]))
    }
}