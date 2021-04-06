use anyhow::{anyhow, Context, Result};
use bytes::{
    buf::{ext::Take, BufExt},
    Buf, BufMut,
};
use ieee80211::{
    FragmentSequenceTrait, Frame, FrameLayer, FrameSubtype, FrameTrait, ManagementFrame,
    ManagementFrameTrait, ManagementSubtype, OptionalTaggedParametersTrait, TagName,
};
use log::{debug, info, warn};
use pcap::{Active, Capture, Offline, Packet};
use radiotap::RadiotapIterator;

use std::{borrow::Borrow, env, fmt};

fn discard_remaining<B: Buf>(mut taken: Take<B>) -> B {
    taken.advance(taken.remaining());
    taken.into_inner()
}

trait Emitable {
    fn emit(&self, buffer: impl BufMut) -> Result<()>;
}

trait Parseable: Sized {
    fn parse(buffer: impl Buf) -> Result<Self>;
}

trait CaptureInterface: Sized {
    fn from_args(args: env::Args) -> Result<Self>;

    fn next(&mut self) -> Result<Packet>;

    fn inject<B: Borrow<[u8]>>(&mut self, packet: B) -> Result<()>;
}

impl CaptureInterface for Capture<Active> {
    fn from_args(mut args: env::Args) -> Result<Self> {
        let device = args.nth(1).ok_or_else(|| anyhow!("No device name given"))?;

        info!("Capturing from device {}", device);
        Capture::from_device(device.as_ref())
            .with_context(|| format!("Failed to create capture from device {}", device))?
            .immediate_mode(true)
            .promisc(true)
            .open()
            .context("Failed to open device")
    }

    fn next(&mut self) -> Result<Packet> {
        self.next().map_err(Into::into)
    }

    fn inject<B: Borrow<[u8]>>(&mut self, packet: B) -> Result<()> {
        self.sendpacket(packet)
            .context("failed to write packet to pcap instance")
    }
}

impl CaptureInterface for Capture<Offline> {
    fn from_args(mut args: env::Args) -> Result<Self> {
        let file = args
            .nth(1)
            .ok_or_else(|| anyhow!("No capture file given"))?;

        info!("Replaying file {}", file);
        Capture::from_file(&file)
            .with_context(|| format!("Failed to read capture file from {}", file))
    }

    fn next(&mut self) -> Result<Packet> {
        self.next().map_err(Into::into)
    }

    fn inject<B: Borrow<[u8]>>(&mut self, packet: B) -> Result<()> {
        debug!("Would've written packet: {:02x?}", packet.borrow());
        Ok(())
    }
}

#[derive(Debug)]
#[repr(packed)]
struct VendorSpecificTag {
    oui: [u8; 3],
    oui_type: u8,
}

impl Parseable for VendorSpecificTag {
    fn parse(mut buffer: impl Buf) -> Result<Self> {
        if buffer.remaining() >= 4 {
            Ok(Self {
                oui: [buffer.get_u8(), buffer.get_u8(), buffer.get_u8()],
                oui_type: buffer.get_u8(),
            })
        } else {
            Err(anyhow!(
                "vendor specific tag to short to contain OUI and type"
            ))
        }
    }
}

fn parse_probe_request(frame: &ManagementFrame) -> Result<Option<StreetpassTag>> {
    let parameters = frame
        .iter_tagged_parameters()
        .ok_or_else(|| anyhow!("frame contains no parameters"))?;

    for parameter in parameters {
        if let Ok((TagName::Other(0xdd), mut data)) = parameter {
            match VendorSpecificTag::parse(&mut data)
                .with_context(|| "invalid vendor specific tag")?
            {
                VendorSpecificTag {
                    oui: [0x00, 0x1f, 0x32],
                    oui_type: 1,
                } => {
                    debug!(
                        "Found possible Nintendo Streetpass tag of length {}",
                        data.remaining()
                    );
                    return Some(StreetpassTag::parse(&mut data)).transpose();
                }
                tag => debug!(
                    "Unhandled OUI tag {:02x} by {:02x}:{:02x}:{:02x}",
                    tag.oui_type, tag.oui[0], tag.oui[1], tag.oui[2],
                ),
            }
        };
    }

    Ok(None)
}

fn shorten(buffer: &[u8], limit: usize) -> &[u8] {
    if limit < buffer.len() {
        &buffer[..limit]
    } else {
        buffer
    }
}

fn dump_rt(buffer: &[u8]) -> Result<()> {
    let (_attributes, payload) = RadiotapIterator::parse(buffer)
        .with_context(|| format!("Invalid radiotap message ({:02x?} ...)", buffer))?;
    debug!("payload: {:02x?} ...", shorten(buffer, 32));

    if let Some(FrameLayer::Management(frame)) = Frame::new(payload).next_layer() {
        debug!(
            "Recieved a management frame: {:?} => {:?}",
            frame.source_address(),
            frame.receiver_address()
        );

        if let FrameSubtype::Management(ManagementSubtype::ProbeRequest) = frame.subtype() {
            match parse_probe_request(&frame) {
                Err(e) => warn!(
                    "failed to parse Streetpass tag from management frame: {}",
                    e
                ),
                Ok(None) => debug!("management frame did not contain a Streetpass tag"),
                Ok(Some(tag)) => info!(
                    "[{:>4}] Beacon from {}: {:08x} advertises {:>2} service(s)",
                    frame.sequence_number(),
                    frame
                        .source_address()
                        .map(|addr| format!("{}", addr))
                        .unwrap_or_else(|| "??:??:??:??:??:??".into()),
                    tag.console_id(),
                    tag.services().len()
                ),
            }
        }
    } else {
        debug!("payload was not an IEEE802.11 management frame")
    };

    Ok(())
}

#[derive(Debug)]
struct StreetpassService {
    id: u32,
    flags: u8,
}

impl Parseable for StreetpassService {
    fn parse(mut buffer: impl Buf) -> Result<Self> {
        if buffer.remaining() >= 5 {
            Ok(Self {
                id: buffer.get_u32(),
                flags: buffer.get_u8(),
            })
        } else {
            Err(anyhow!("buffer to short to parse StreetpassService"))
        }
    }
}

impl Emitable for StreetpassService {
    fn emit(&self, mut buffer: impl BufMut) -> Result<()> {
        if buffer.remaining_mut() >= 5 {
            buffer.put_u32(self.id);
            buffer.put_u8(self.flags);
            Ok(())
        } else {
            Err(anyhow!(
                "not enough space in buffer to emit StreetpassService"
            ))
        }
    }
}

impl fmt::LowerHex for StreetpassService {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#08x}", self.id)?;

        if self.flags != 0 {
            write!(f, ":{:08b}", self.flags)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
struct StreetpassTag {
    services: Vec<StreetpassService>,
    console_id: u64,
}

impl Parseable for StreetpassTag {
    fn parse(mut buffer: impl Buf) -> Result<Self> {
        let mut services = None;
        let mut console_id = None;

        while buffer.remaining() >= 2 {
            let id = buffer.get_u8();
            let len = buffer.get_u8() as usize;
            let mut tag_data = buffer.take(len);

            match id {
                0x11 => {
                    services = {
                        let mut services = Vec::with_capacity(tag_data.remaining());

                        while tag_data.has_remaining() {
                            services.push(StreetpassService::parse(&mut tag_data)?);
                        }

                        Some(services)
                    };
                }
                0xf0 if tag_data.remaining() == 8 => {
                    console_id = Some(tag_data.get_u64());
                }
                _ => debug!(
                    "Unknown Streetpass tag attribute {:02x} of length {}",
                    id, len
                ),
            };

            buffer = discard_remaining(tag_data);
        }

        Ok(Self {
            services: services.unwrap_or_default(),
            console_id: console_id
                .ok_or_else(|| anyhow!("Streetpass tag did not contain a console ID"))?,
        })
    }
}

impl Emitable for StreetpassTag {
    fn emit(&self, mut buffer: impl BufMut) -> Result<()> {
        use std::convert::TryInto;
        if buffer.remaining_mut() >= 4 + 8 {
            buffer.put_u8(0x11);
            let len: u8 = self
                .services()
                .len()
                .try_into()
                .with_context(|| anyhow!("Too many services attached to StreetpassTag"))?;

            buffer.put_u8(len);

            for service in self.services.iter() {
                service.emit(&mut buffer)?;
            }

            buffer.put_u8(0xf0);
            buffer.put_u8(8);
            buffer.put_u64(self.console_id);

            Ok(())
        } else {
            Err(anyhow!("Not enough space in buffer to emit StreetpassTag"))
        }
    }
}

impl StreetpassTag {
    pub fn console_id(&self) -> u64 {
        self.console_id
    }

    pub fn services(&self) -> &[StreetpassService] {
        &self.services
    }
}

fn main() -> Result<()> {
    pretty_env_logger::init();

    let mut capture = Capture::<Active>::from_args(env::args())?;

    while let Ok(packet) = capture.next() {
        debug!("packet: {:?}", packet);
        dump_rt(packet.data).unwrap_or_else(|e| warn!("Failed to dump radiotap header: {}", e))
    }

    Ok(())
}
