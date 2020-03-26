use netlink_packet_core::DecodeError;

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
         |s: &str| { s.len() + 1 }
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
                            $kind => {
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

/// GenericBuffer:
/// 0               1               2               3
/// 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Command    |    Version    |          Reserved            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Attributes                         |
/// |                             ...                             |
/// |                                                             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

pub struct GenericBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> GenericBuffer<T> {
    pub fn new(buffer: T) -> Self {
        Self { buffer }
    }

    pub fn length(&self) -> usize {
        self.buffer.as_ref().len()
    }

    pub fn new_checked(buffer: T) -> Result<Self, DecodeError> {
        Ok(Self::new(buffer))
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> GenericBuffer<&'a T> {
    pub fn inner(&self) -> &'a [u8] {
        &self.buffer.as_ref()[..]
    }

    pub fn command(&self) -> u8 {
        self.inner()[0]
    }

    pub fn version(&self) -> u8 {
        self.inner()[1]
    }

    pub fn attributes(&self) -> &'a [u8] {
        &self.inner()[4..]
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> GenericBuffer<&'a mut T> {
    pub fn inner_mut(&mut self) -> &mut [u8] {
        &mut self.buffer.as_mut()[..]
    }
}
