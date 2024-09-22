use std::ffi::c_void;
use std::fmt::Debug;
use std::io;
use std::mem::size_of;
use std::net::{Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::os::fd::FromRawFd;
use std::str::FromStr;

use crate::mdns::constants::{IPV6_MULTICAST_ADDRESS, MDNS_PORT};
use crate::{log_error, NetworkInterface};
use libc::{bind, c_char, in6_addr, perror, setsockopt, sockaddr, sockaddr_in6, socket, socklen_t, AF_INET6, SOCK_DGRAM, SOL_SOCKET, SO_REUSEADDR, SO_REUSEPORT};

/// Holds information about the udp_socket constructed via libc and the buffer corresponding for data.
pub struct MulticastSocket<const C: usize> {
    udp_socket: UdpSocket,
    pub buffer: [u8; C],
}

impl MulticastSocket<2000> {
    /// Constructs a new MulticastSocket instance which binds to 5353 port and allows for ADDR and PORT reuse.
    pub fn new(interface: &NetworkInterface, port: u16) -> Self {
        let multicast_ipv6 = Ipv6Addr::from_str(IPV6_MULTICAST_ADDRESS).unwrap();
        let fd = unsafe { socket(AF_INET6, SOCK_DGRAM, 0) };
        let option_value = 1;
        let cc = &option_value as *const _;

        let socket = match interface.do_custom {
            false => UdpSocket::bind(format!("[::%{}]:{}", interface.index, MDNS_PORT)).expect("Unable to bind to tcp..."),
            true => {
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
                        let error_text = "FIRST OPT FAILED" as *const _;
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
                        let error_text = "SECOND OPT FAILED" as *const _;
                        perror(error_text as *const c_char);
                    }
                    if bind(fd, x, size_of::<sockaddr_in6>() as socklen_t) < 0 {
                        let error_text = "BIND FAILED" as *const _;
                        perror(error_text as *const c_char);
                    }
                    UdpSocket::from_raw_fd(fd)
                }
            }
        };
        socket.join_multicast_v6(&multicast_ipv6, interface.index).expect("Unable to join...");
        Self {
            udp_socket: socket,
            buffer: [0u8; 2000],
        }
    }

    pub fn send<A: ToSocketAddrs + Debug + Copy>(&self, buf: &[u8], destination: A) {
        if let Err(error) = self.udp_socket.send_to(buf, destination) {
            log_error!("Unable to send to {:?} due to {:?}", destination, error);
        }
    }

    pub fn receive_from(&mut self) -> io::Result<(usize, SocketAddr)> {
        self.udp_socket.recv_from(&mut self.buffer)
    }
}
