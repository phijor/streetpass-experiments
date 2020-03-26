mod constants;
mod controller;
mod genl;

use crate::controller::{ControlMessage, FamilyName};

use netlink_packet_core::{NetlinkMessage, NLM_F_ACK, NLM_F_MATCH, NLM_F_REQUEST, NLM_F_ROOT};
use netlink_sys::{Protocol, Socket, SocketAddr};

fn main() {
    let get_family = ControlMessage::GetFamily(FamilyName::new("nl80211"));
    let mut packet = NetlinkMessage::from(get_family);
    packet.header.flags = NLM_F_REQUEST | NLM_F_ACK;
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
            }
        }
    }
}
