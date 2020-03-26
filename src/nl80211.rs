use byteorder::{ByteOrder, NativeEndian};
use failure::{Compat, ResultExt};
use netlink_packet_core::{
    NetlinkDeserializable, NetlinkHeader, NetlinkMessage, NetlinkPayload, NetlinkSerializable,
};
use netlink_packet_utils::{
    nla::{Nla, NlaBuffer, NlasIterator},
    parsers,
    traits::{Emitable, Parseable, ParseableParametrized},
    DecodeError,
};

use crate::controller::{FamilyId, NewFamily};

const NL80211_CMD_GET_INTERFACE: u8 = 5;

const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_IFNAME: u16 = 4;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct InterfaceIndex(u32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceName(String);

impl_wrapped_attribute!(InterfaceIndex(u32): NL80211_ATTR_IFINDEX);
impl_wrapped_attribute!(InterfaceName(String): NL80211_ATTR_IFNAME);

impl InterfaceIndex {
    fn from_name(name: &str) -> std::io::Result<Self> {
        extern "C" {
            fn if_nametoindex(ifname: *const libc::c_char) -> libc::c_uint;
        }

        let res = unsafe { if_nametoindex(name.as_ptr() as *const libc::c_char) };

        match res {
            0 => Err(std::io::Error::last_os_error()),
            index => Ok(Self(index)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nl80221Message {
    GetInterface(InterfaceIndex),
}

#[derive(Debug)]
pub struct Nl80221Family {
    pub family: NewFamily,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nl80221TaggedMessage {
    family_id: FamilyId,
    pub message: Nl80221Message,
}

impl Nl80221Family {
    pub fn new(family: NewFamily) -> Self {
        Self { family }
    }

    pub fn tag_message(&self, message: Nl80221Message) -> Nl80221TaggedMessage {
        Nl80221TaggedMessage {
            message,
            family_id: self.family.id.clone(),
        }
    }
}

impl Nl80221Message {
    fn attribute_size(&self) -> usize {
        match self {
            Self::GetInterface(index) => index.buffer_len(),
        }
    }

    fn command(&self) -> u8 {
        match self {
            Self::GetInterface(_) => NL80211_CMD_GET_INTERFACE,
        }
    }

    fn version(&self) -> u8 {
        0
    }

    fn emit_attributes(&self, buffer: &mut [u8]) {
        match self {
            Self::GetInterface(index) => index.emit(buffer),
        }
    }
}

impl NetlinkSerializable<Nl80221TaggedMessage> for Nl80221TaggedMessage {
    fn buffer_len(&self) -> usize {
        4 + self.message.attribute_size()
    }

    fn message_type(&self) -> u16 {
        self.family_id.clone().into()
    }

    fn serialize(&self, buffer: &mut [u8]) {
        buffer[0] = self.message.command();
        buffer[1] = self.message.version();
        buffer[2] = 0;
        buffer[3] = 0;

        self.message.emit_attributes(&mut buffer[4..]);
    }
}

impl From<Nl80221TaggedMessage> for NetlinkPayload<Nl80221TaggedMessage> {
    fn from(message: Nl80221TaggedMessage) -> Self {
        Self::InnerMessage(message)
    }
}
