mod constants;
mod genl;

use crate::genl::{ControlMessage, GenericMessage};

use netlink_packet_core::{NetlinkMessage, NLM_F_ACK, NLM_F_MATCH, NLM_F_REQUEST, NLM_F_ROOT};
use netlink_sys::{Protocol, Socket, SocketAddr};

fn main() {
    let generic = GenericMessage::from(ControlMessage::GetFamily("nl80211\0".into()));
    let mut packet = NetlinkMessage::from(generic);
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

    let mut recv_buf = vec![0; 1024];

    loop {
        let (n, _addr) = socket.recv_from(&mut recv_buf, 0).unwrap();
        match n {
            0 => break,
            _ => println!("received: {:02x?}", &recv_buf[..n]),
        }
    }
}
