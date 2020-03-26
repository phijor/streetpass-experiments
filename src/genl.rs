use netlink_packet_core::DecodeError;

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
