use crate::constants::*;

use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_core::{
    NetlinkDeserializable, NetlinkHeader, NetlinkMessage, NetlinkPayload, NetlinkSerializable,
    NLMSG_ALIGNTO, NLM_F_ACK, NLM_F_REQUEST,
};
use netlink_packet_utils::traits::Emitable;

use std::ffi::CString;

/// Layout:
/// 0               1               2               3
/// 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ NetlinkHeader
/// |                          Length                             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            Type              |           Flags              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Sequence Number                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Process ID (PID)                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ GenericHeader
/// |   Command    |    Version    |          Reserved            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Attributes                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribute {
    Unspecified,
    U8(u8),
    U16(u16),
    U32(u32),
    Flag(bool),
    MilliSeconds(u64),
    String(String),
    NulTerminatedString(CString),
    Nested(Vec<Attribute>),
    Custom(u16, Vec<u8>),
}

#[inline]
fn nl_align(length: usize) -> usize {
    const MASK: usize = (NLMSG_ALIGNTO as usize) - 1;
    (length + MASK) & !MASK
}

fn attr_list_buffer_size(attributes: &[Attribute]) -> usize {
    attributes
        .iter()
        .map(|attr| nl_align(attr.buffer_len()))
        .sum()
}

impl Attribute {
    fn length(&self) -> usize {
        match self {
            Attribute::Unspecified => 0,
            Attribute::U8(_) => 1,
            Attribute::U16(_) => 2,
            Attribute::U32(_) => 4,
            Attribute::Flag(_) => 1,
            Attribute::MilliSeconds(_) => 8,
            Attribute::String(s) => s.len(),
            Attribute::NulTerminatedString(cstr) => cstr.as_bytes_with_nul().len(),
            Attribute::Nested(attrs) => attr_list_buffer_size(&attrs),
            Attribute::Custom(_id, data) => data.len(),
        }
    }

    fn type_id(&self) -> u16 {
        match self {
            Attribute::Unspecified => 0,
            Attribute::U8(_) => 1,
            Attribute::U16(_) => 2,
            Attribute::U32(_) => 3,
            Attribute::Flag(_) => 4,
            Attribute::MilliSeconds(_) => 5,
            Attribute::String(_) => 6, /* TODO: split type id from attribute type! */
            Attribute::NulTerminatedString(_) => 7,
            Attribute::Nested(_) => 8,
            Attribute::Custom(id, _data) => *id,
        }
    }

    const fn header_size(&self) -> usize {
        4
    }
}

impl Emitable for Attribute {
    fn buffer_len(&self) -> usize {
        self.header_size() + dbg!(nl_align(self.length()))
    }

    fn emit(&self, buffer: &mut [u8]) {
        eprintln!("Attribute::emit: buffer_len = {}", buffer.len());
        NativeEndian::write_u16(&mut buffer[0..2], self.buffer_len() as u16);
        NativeEndian::write_u16(&mut buffer[2..4], self.type_id());

        let payload = &mut buffer[4..];
        match self {
            Attribute::Unspecified => {}
            Attribute::U8(v) => payload[0] = *v,
            Attribute::U16(v) => NativeEndian::write_u16(payload, *v),
            Attribute::U32(v) => NativeEndian::write_u32(payload, *v),
            Attribute::Flag(flag) => payload[0] = if *flag { 1 } else { 0 },
            Attribute::MilliSeconds(ms) => NativeEndian::write_u64(payload, *ms),
            Attribute::String(s) => payload[..s.len()].copy_from_slice(s.as_bytes()),
            Attribute::NulTerminatedString(cstr) => {
                let bytes = cstr.as_bytes_with_nul();
                payload[..bytes.len()].copy_from_slice(bytes)
            }
            Attribute::Nested(attrs) => {
                let mut next_payload = payload;
                for attr in attrs {
                    let length = nl_align(attr.buffer_len());
                    let (cur, next) = next_payload.split_at_mut(length);
                    attr.emit(cur);
                    next_payload = next;
                }
            }
            Attribute::Custom(_id, data) => payload[..data.len()].copy_from_slice(data.as_slice()),
        }
    }
}

pub trait Generic {
    fn command(&self) -> u8;

    fn version(&self) -> u8 {
        1
    }

    fn family_id(&self) -> u16;

    fn attributes(self) -> Vec<Attribute>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    GetFamily(String),
}

impl Generic for ControlMessage {
    fn command(&self) -> u8 {
        match self {
            ControlMessage::GetFamily(_) => CTRL_CMD_GETFAMILY,
        }
    }

    fn family_id(&self) -> u16 {
        0x10
    }

    fn attributes(self) -> Vec<Attribute> {
        match self {
            ControlMessage::GetFamily(family) => vec![Attribute::String(family)],
        }
    }
}

impl<G: Generic> From<G> for GenericMessage {
    fn from(generic: G) -> Self {
        Self {
            command: generic.command(),
            version: generic.version(),
            message_type: generic.family_id(),
            attributes: generic.attributes(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericMessage {
    command: u8,
    version: u8,
    message_type: u16,
    attributes: Vec<Attribute>,
}

impl GenericMessage {
    const fn header_size(&self) -> usize {
        4
    }

    fn attribute_size(&self) -> usize {
        attr_list_buffer_size(&self.attributes)
    }
}

impl Emitable for GenericMessage {
    fn buffer_len(&self) -> usize {
        self.header_size() + self.attribute_size()
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer[0] = self.command;
        buffer[1] = self.version;
        buffer[2] = 0;
        buffer[3] = 0;

        let mut payload = &mut buffer[4..];
        for attr in self.attributes.iter() {
            let length = attr.buffer_len();
            eprintln!(
                "GenericMessage::emit: payload_len = {}, attr_len = {}",
                payload.len(),
                length
            );
            let (cur, next) = dbg!(payload.split_at_mut(length));
            attr.emit(cur);
            payload = next;
        }
    }
}

impl NetlinkSerializable<GenericMessage> for GenericMessage {
    fn message_type(&self) -> u16 {
        self.message_type
    }

    fn buffer_len(&self) -> usize {
        <Self as Emitable>::buffer_len(self)
    }

    fn serialize(&self, buffer: &mut [u8]) {
        eprintln!("GenericMessage::serialize: buffer_len = {:?}", buffer.len());
        self.emit(buffer)
    }
}

impl From<GenericMessage> for NetlinkPayload<GenericMessage> {
    fn from(message: GenericMessage) -> Self {
        NetlinkPayload::InnerMessage(message)
    }
}
