use byteorder::{ByteOrder, NativeEndian};
use failure::{Compat, ResultExt};
use netlink_packet_core::{
    NetlinkDeserializable, NetlinkHeader, NetlinkPayload, NetlinkSerializable,
};
use netlink_packet_utils::{
    nla::{Nla, NlaBuffer, NlasIterator},
    parsers,
    traits::{Emitable, Parseable, ParseableParametrized},
    DecodeError,
};

use crate::genl::GenericBuffer;

pub const CTRL_CMD_UNSPEC: u8 = 0;
pub const CTRL_CMD_NEWFAMILY: u8 = 1;
pub const CTRL_CMD_DELFAMILY: u8 = 2;
pub const CTRL_CMD_GETFAMILY: u8 = 3;
pub const CTRL_CMD_NEWOPS: u8 = 4;
pub const CTRL_CMD_DELOPS: u8 = 5;
pub const CTRL_CMD_GETOPS: u8 = 6;
pub const CTRL_CMD_NEWMCAST_GRP: u8 = 7;
pub const CTRL_CMD_DELMCAST_GRP: u8 = 8;
#[allow(unused)]
pub const CTRL_CMD_GETMCAST_GRP: u8 = 9;

#[allow(unused)]
pub const CTRL_ATTR_UNSPEC: u16 = 0;
pub const CTRL_ATTR_FAMILY_ID: u16 = 1;
pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;
pub const CTRL_ATTR_VERSION: u16 = 3;
pub const CTRL_ATTR_HDRSIZE: u16 = 4;
pub const CTRL_ATTR_MAXATTR: u16 = 5;
pub const CTRL_ATTR_OPS: u16 = 6;
pub const CTRL_ATTR_MCAST_GROUPS: u16 = 7;

#[allow(unused)]
pub const CTRL_ATTR_OP_UNSPEC: u16 = 0;
pub const CTRL_ATTR_OP_ID: u16 = 1;
pub const CTRL_ATTR_OP_FLAGS: u16 = 2;

#[allow(unused)]
pub const CTRL_ATTR_MCAST_GRP_UNSPEC: u16 = 0;
pub const CTRL_ATTR_MCAST_GRP_NAME: u16 = 1;
pub const CTRL_ATTR_MCAST_GRP_ID: u16 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FamilyId(u16);

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FamilyName(String);

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Version(u32);

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HeaderSize(u32);

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MaxAttributes(u32);

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OperationId(u32);

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OperationFlags(u32);

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MulticastGroupId(u32);

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MulticastGroupName(String);

impl_wrapped_attribute!(FamilyId(u16): CTRL_ATTR_FAMILY_ID);
impl_wrapped_attribute!(FamilyName(String): CTRL_ATTR_FAMILY_NAME);
impl_wrapped_attribute!(Version(u32): CTRL_ATTR_VERSION);
impl_wrapped_attribute!(HeaderSize(u32): CTRL_ATTR_HDRSIZE);
impl_wrapped_attribute!(MaxAttributes(u32): CTRL_ATTR_MAXATTR);

impl_wrapped_attribute!(OperationId(u32): CTRL_ATTR_OP_ID);
impl_wrapped_attribute!(OperationFlags(u32): CTRL_ATTR_OP_FLAGS);

impl_wrapped_attribute!(MulticastGroupId(u32): CTRL_ATTR_MCAST_GRP_ID);
impl_wrapped_attribute!(MulticastGroupName(String): CTRL_ATTR_MCAST_GRP_NAME);

impl FamilyName {
    pub fn new<T: Into<String>>(s: T) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Operation {
    id: OperationId,
    flags: OperationFlags,
}

impl_nested_attribute_parse! {
    Operation:
        CTRL_ATTR_OP_ID => id: OperationId,
        CTRL_ATTR_OP_FLAGS => flags: OperationFlags,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MulticastGroup {
    id: MulticastGroupId,
    name: MulticastGroupName,
}

impl_nested_attribute_parse! {
    MulticastGroup:
        CTRL_ATTR_MCAST_GRP_NAME => name: MulticastGroupName,
        CTRL_ATTR_MCAST_GRP_ID => id: MulticastGroupId
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OperationList {
    operations: Vec<Operation>,
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>> for OperationList {
    fn parse(buffer: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let operations = NlasIterator::new(buffer.value())
            .map(|attribute: Result<NlaBuffer<_>, _>| {
                attribute.and_then(|attr| Operation::parse(&attr.value()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { operations })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MulticastGroupList {
    groups: Vec<MulticastGroup>,
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>> for MulticastGroupList {
    fn parse(buffer: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
        let groups = NlasIterator::new(buffer.value())
            .map(|attribute: Result<NlaBuffer<_>, _>| {
                attribute.and_then(|attr| MulticastGroup::parse(&attr.value()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { groups })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewFamily {
    pub id: FamilyId,
    pub name: FamilyName,
    pub version: Version,
    pub header_size: HeaderSize,
    pub max_attributes: MaxAttributes,
    pub operations: OperationList,
    pub multicast_groups: MulticastGroupList,
}

impl_nested_attribute_parse! {
    NewFamily:
        CTRL_ATTR_FAMILY_NAME => name: FamilyName,
        CTRL_ATTR_FAMILY_ID => id: FamilyId,
        CTRL_ATTR_VERSION => version: Version,
        CTRL_ATTR_HDRSIZE => header_size: HeaderSize,
        CTRL_ATTR_MAXATTR => max_attributes: MaxAttributes,
        CTRL_ATTR_OPS => operations: OperationList,
        CTRL_ATTR_MCAST_GROUPS => multicast_groups: MulticastGroupList,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    NewFamily(NewFamily),
    GetFamily(FamilyName),
}

impl ControlMessage {
    pub fn attribute_size(&self) -> usize {
        match self {
            ControlMessage::NewFamily(family) => family.id.buffer_len() + family.name.buffer_len(),
            ControlMessage::GetFamily(name) => name.buffer_len(),
        }
    }

    fn command(&self) -> u8 {
        match self {
            ControlMessage::NewFamily(_) => CTRL_CMD_NEWFAMILY,
            ControlMessage::GetFamily(_) => CTRL_CMD_GETFAMILY,
        }
    }

    fn version(&self) -> u8 {
        match self {
            ControlMessage::NewFamily(_) => 2,
            _ => 1,
        }
    }

    fn emit_attributes(&self, buffer: &mut [u8]) {
        match self {
            ControlMessage::NewFamily(_family) => unimplemented!(),
            ControlMessage::GetFamily(name) => name.emit(buffer),
        }
    }
}

impl NetlinkSerializable<ControlMessage> for ControlMessage {
    fn buffer_len(&self) -> usize {
        4 + self.attribute_size()
    }

    fn message_type(&self) -> u16 {
        0x10
    }

    fn serialize(&self, buffer: &mut [u8]) {
        buffer[0] = self.command();
        buffer[1] = self.version();
        buffer[2] = 0;
        buffer[3] = 0;

        self.emit_attributes(&mut buffer[4..]);
    }
}

impl From<ControlMessage> for NetlinkPayload<ControlMessage> {
    fn from(message: ControlMessage) -> Self {
        NetlinkPayload::InnerMessage(message)
    }
}

impl<'buffer, B: AsRef<[u8]> + ?Sized> ParseableParametrized<GenericBuffer<&'buffer B>, u16>
    for ControlMessage
{
    fn parse_with_param(
        buffer: &GenericBuffer<&'buffer B>,
        message_type: u16,
    ) -> Result<Self, DecodeError> {
        match message_type {
            0x10 => match buffer.command() {
                CTRL_CMD_NEWFAMILY => {
                    let new_family = NewFamily::parse(&buffer.attributes())?;

                    Ok(ControlMessage::NewFamily(new_family))
                }
                cmd => Err(format!("unsupported command {}", cmd).into()),
            },
            t => Err(format!("unknown message type {}", t).into()),
        }
    }
}

impl NetlinkDeserializable<ControlMessage> for ControlMessage {
    type Error = Compat<DecodeError>;

    fn deserialize(header: &NetlinkHeader, payload: &[u8]) -> Result<Self, Self::Error> {
        let generic_buffer = GenericBuffer::new_checked(payload).compat()?;
        ControlMessage::parse_with_param(&generic_buffer, header.message_type).compat()
    }
}
