#[macro_use]
mod genl;

mod constants;
mod controller;
mod nl80211;

use crate::{
    controller::{ControlMessage, FamilyName, NewFamily},
    nl80211::{Nl80221Family, Nl80221Message},
};

use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_MATCH, NLM_F_REQUEST, NLM_F_ROOT,
};
use netlink_sys::{Protocol, Socket, SocketAddr};

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};

use std::io::{Error, Result};

#[derive(Debug)]
struct PacketSocket(RawFd);

impl PacketSocket {
    pub fn open() -> Result<Self> {
        let fd = unsafe { libc::socket(libc::PF_PACKET, libc::SOCK_RAW, libc::ETH_P_ALL.to_be()) };
        if fd < 0 {
            Err(Error::last_os_error())
        } else {
            Ok(Self(fd))
        }
    }
}

impl AsRawFd for PacketSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

fn main() {
    let get_family = ControlMessage::GetFamily(FamilyName::new("nl80211"));
    let mut packet = NetlinkMessage::from(get_family);
    packet.header.flags = NLM_F_REQUEST;
    packet.finalize();

    let mut buf = vec![0; packet.header.length as usize];
    packet.serialize(&mut buf);

    println!("packet: {:02x?}", packet);
    println!("buffer: {:02x?}", buf);

    let kernel_unicast = SocketAddr::new(0, 0);
    let socket = Socket::new(Protocol::Generic).unwrap();

    socket
        .send_to(&buf[..packet.buffer_len()], &kernel_unicast, 0)
        .unwrap();

    let mut recv_buf = vec![0; 4096];

    loop {
        let (n, _addr) = socket.recv_from(&mut recv_buf, 0).unwrap();
        match n {
            0 => break,
            _ => {
                let response_buf = &recv_buf[..n];
                let response = NetlinkMessage::<ControlMessage>::deserialize(response_buf);
                println!("received: {:02x?}", response_buf);
                println!("response: {:#02x?}", response);

                if let Ok(NetlinkMessage {
                    payload: NetlinkPayload::InnerMessage(ControlMessage::NewFamily(new_family)),
                    ..
                }) = response
                {
                    get_iface(&socket, Nl80221Family::new(new_family))
                }
            }
        }
    }
}

fn get_iface(socket: &Socket, nl80211: Nl80221Family) {
    let get_iface = nl80211.tag_message(Nl80221Message::GetInterface(13.into()));
    let mut packet = NetlinkMessage::from(get_iface);
    packet.header.flags = NLM_F_REQUEST;
    packet.finalize();

    let mut buf = vec![0; packet.header.length as usize];
    packet.serialize(&mut buf);

    let send_buf = &buf[..packet.buffer_len()];
    println!("get_family: {:02x?}", packet);
    println!("sending get_family: {:02x?}", send_buf);
    socket.send_to(send_buf, &SocketAddr::new(0, 0), 0).unwrap();

    let mut recv_buf = vec![0; 4096];

    loop {
        let (n, _addr) = socket.recv_from(&mut recv_buf, 0).unwrap();
        match n {
            0 => break,
            n => {
                let response_buf = &recv_buf[..n];
                println!("received: {:02x?}", response_buf);
            }
        }
    }
}
