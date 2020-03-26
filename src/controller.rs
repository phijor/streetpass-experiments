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

pub(crate) mod constants {
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
}

macro_rules! missing {
    ($attr: expr) => {
        || DecodeError::from(concat!("attribute ", $attr, " is missing"))
    };
}

macro_rules! impl_wrapped_attribute {
    ($attr: ident ($type: tt): $kind: expr $(,)?) => {
        impl Nla for $attr {
            fn value_len(&self) -> usize {
                impl_wrapped_attribute!(@length($type))(&self.0)
            }

            fn kind(&self) -> u16 {
                $kind
            }

            fn emit_value(&self, buffer: &mut [u8]) {
                impl_wrapped_attribute!(@emit(self.0) as $type in buffer)
            }
        }

        impl<'buffer, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'buffer T>> for $attr {
            fn parse(buffer: &NlaBuffer<&'buffer T>) -> Result<Self, DecodeError> {
                impl_wrapped_attribute!(@parse(buffer.value()) as $type in $attr)
            }
        }

        impl From<$type> for $attr {
            fn from(v: $type) -> Self {
                Self(v)
            }
        }

        impl From<$attr> for $type {
            fn from(attr: $attr) -> Self {
            attr.0
            }
        }

    };
    (@length(String)) => {
        String::len
    };
    (@length($_: tt)) => {
        std::mem::size_of_val
    };
    (@parse($value: expr) as $type: tt in $attr: ident) => {
        impl_wrapped_attribute!(@parse($value) as $type).map($attr)
    };
    (@parse($value: expr) as u16 ) => {
        parsers::parse_u16($value)
    };
    (@parse($value: expr) as u32) => {
        parsers::parse_u32($value)
    };
    (@parse($value: expr) as String) => {
        parsers::parse_string($value)
    };
    (@emit($value: expr) as u16 in $buffer: ident) => {
        NativeEndian::write_u16($buffer, $value)
    };
    (@emit($value: expr) as u32 in $buffer: ident) => {
        NativeEndian::write_u32($buffer, $value)
    };
    (@emit($value: expr) as String in $buffer: ident) => {
        $buffer[..$value.len()].copy_from_slice($value.as_bytes())
    };
}

macro_rules! impl_nested_attribute_parse {
    ($attr: ident: $($kind: tt => $field: tt: $type: tt),+ $(,)?) => {
        impl<T: AsRef<[u8]>> Parseable<T> for $attr {
            fn parse(buffer: &T) -> Result<Self, DecodeError> {
                $(let mut $field = None;)*

                for attribute in NlasIterator::new(buffer) {
                    let attribute = attribute?;
                    match attribute.kind() {
                        $(
                            constants::$kind => {
                                $field.replace($type::parse(&attribute)?);
                            }
                        )*
                        kind => {
                            return Err(format!(
                                concat!("encountered unexpected kind {} when parsing ", stringify!($attr)),
                                kind
                            )
                            .into())
                        }
                    }
                }

                Ok(Self {
                    $(
                        $field: $field
                            .ok_or_else(||
                                DecodeError::from(
                                    concat!(
                                        "missing attribute ",
                                        stringify!($kind),
                                        " when parsing ",
                                        stringify!($attr)
                                    )
                                )
                            )?
                    ),*
                })
            }
        }
    };
}

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

impl_wrapped_attribute!(FamilyId(u16): constants::CTRL_ATTR_FAMILY_ID);
impl_wrapped_attribute!(FamilyName(String): constants::CTRL_ATTR_FAMILY_NAME);
impl_wrapped_attribute!(Version(u32): constants::CTRL_ATTR_VERSION);
impl_wrapped_attribute!(HeaderSize(u32): constants::CTRL_ATTR_HDRSIZE);
impl_wrapped_attribute!(MaxAttributes(u32): constants::CTRL_ATTR_MAXATTR);

impl_wrapped_attribute!(OperationId(u32): constants::CTRL_ATTR_OP_ID);
impl_wrapped_attribute!(OperationFlags(u32): constants::CTRL_ATTR_OP_FLAGS);

impl_wrapped_attribute!(MulticastGroupId(u32): constants::CTRL_ATTR_MCAST_GRP_ID);
impl_wrapped_attribute!(MulticastGroupName(String): constants::CTRL_ATTR_MCAST_GRP_NAME);

impl FamilyName {
    pub fn new<T: Into<String>>(s: T) -> Self {
        Self(s.into())
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
    id: FamilyId,
    name: FamilyName,
    version: Version,
    header_size: HeaderSize,
    max_attributes: MaxAttributes,
    operations: OperationList,
    multicast_groups: MulticastGroupList,
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
            ControlMessage::NewFamily(_) => constants::CTRL_CMD_NEWFAMILY,
            ControlMessage::GetFamily(_) => constants::CTRL_CMD_GETFAMILY,
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
                constants::CTRL_CMD_NEWFAMILY => {
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
