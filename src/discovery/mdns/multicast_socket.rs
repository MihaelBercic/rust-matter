use std::ffi::c_void;
use std::mem::size_of;
use std::net::{Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::FromRawFd;
use std::str::FromStr;

use libc::{
    AF_INET6, bind, c_char, in6_addr, perror, setsockopt, SO_REUSEADDR, SO_REUSEPORT, SOCK_DGRAM,
    sockaddr, sockaddr_in6, socket, socklen_t, SOL_SOCKET,
};
use netif::Interface;

use matter::discovery::constants::IPV6_MULTICAST_ADDRESS;

/// Holds information about the udp_socket constructed via libc and the buffer corresponding for data.
pub struct MulticastSocket {
    pub udp_socket: UdpSocket,
    pub buffer: [u8; 9000],
}

impl MulticastSocket {
    /// Constructs a new MulticastSocket instance which binds to 5353 port and allows for ADDR and PORT reuse.
    pub fn new(interface: &Interface, port: u16) -> Self {
        let error_text = "OPT FAILED" as *const _;
        let multicast_ipv6 = Ipv6Addr::from_str(IPV6_MULTICAST_ADDRESS).unwrap();
        let fd = unsafe { socket(AF_INET6, SOCK_DGRAM, 0) };
        let option_value = 1;
        let cc = &option_value as *const _;

        unsafe {
            let x = &sockaddr_in6 {
                sin6_family: 30, // AF_INET6
                sin6_port: port.to_be(),
                sin6_addr: in6_addr { s6_addr: [0u8; 16] },
                sin6_len: 0,
                sin6_flowinfo: 0,
                sin6_scope_id: 0,
            } as *const _ as *const sockaddr;
            if setsockopt(
                fd,
                SOL_SOCKET,
                SO_REUSEADDR,
                cc as *const c_void,
                size_of::<i32>() as socklen_t,
            ) < 0
            {
                perror(error_text as *const c_char);
            }
            if setsockopt(
                fd,
                SOL_SOCKET,
                SO_REUSEPORT,
                cc as *const c_void,
                size_of::<i32>() as socklen_t,
            ) < 0
            {
                perror(error_text as *const c_char);
            }
            if bind(fd, x, size_of::<sockaddr_in6>() as socklen_t) < 0 {
                perror(error_text as *const c_char);
            }
        }
        let socket = unsafe { UdpSocket::from_raw_fd(fd) };
        socket
            .join_multicast_v6(&multicast_ipv6, interface.scope_id().unwrap())
            .expect("Unable to join...");
        return Self {
            udp_socket: socket,
            buffer: [0u8; 9000],
        };
    }

    pub fn receive_from(&mut self) -> std::io::Result<(usize, SocketAddr)> {
        return self.udp_socket.recv_from(&mut self.buffer);
    }
}
