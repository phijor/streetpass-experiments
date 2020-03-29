use anyhow::{anyhow, Context, Result};
use byteorder::{ByteOrder, NetworkEndian};
use ieee80211::{
    Frame, FrameLayer, FrameSubtype, FrameTrait, ManagementFrame, ManagementFrameTrait,
    ManagementSubtype, OptionalTaggedParametersTrait, TagName,
};
use log::{debug, info, warn};
use pcap::{Active, Capture, Offline, Packet};
use radiotap::RadiotapIterator;

use std::{borrow::Borrow, env};

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
            .buffer_size(10 * 4046)
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
struct VendorSpecificTag<'a> {
    data: &'a [u8],
}

impl<'a> VendorSpecificTag<'a> {
    fn new(data: &'a [u8]) -> Result<Self> {
        if data.len() >= 4 {
            Ok(Self { data })
        } else {
            Err(anyhow!(
                "vendor specific tag to short to contain OUI and type"
            ))
        }
    }

    fn oui(&self) -> &[u8; 3] {
        use std::convert::TryInto;
        self.data[0..3].try_into().unwrap()
    }

    fn oui_type(&self) -> u8 {
        self.data[3]
    }

    fn data(&self) -> &[u8] {
        &self.data[4..]
    }
}

fn parse_probe_request(frame: ManagementFrame) -> Result<Option<StreetpassTag>> {
    let parameters = frame
        .iter_tagged_parameters()
        .ok_or_else(|| anyhow!("frame contains no parameters"))?;

    for parameter in parameters {
        if let Ok((TagName::Other(0xdd), data)) = parameter {
            let tag =
                VendorSpecificTag::new(data).with_context(|| "invalid vendor specific tag")?;
            match (tag.oui(), tag.oui_type()) {
                ([0x00, 0x1f, 0x32], 1) => {
                    info!(
                        "Found possible Nintendo Streetpass tag of length {}",
                        tag.data().len()
                    );
                    return Some(StreetpassTag::parse(tag.data())).transpose();
                }
                (oui, type_) => debug!(
                    "Unhandled OUI tag {:02x} by {:02x}:{:02x}:{:02x}",
                    type_, oui[0], oui[1], oui[2],
                ),
            }
        };
    }

    Ok(None)
}

fn dump_rt(buffer: &[u8]) -> Result<()> {
    let (_attributes, payload) =
        RadiotapIterator::parse(buffer).context("Invalid radiotap message")?;
    debug!(
        "payload: {:02x?} ...",
        &payload[..32.min(payload.len() - 1)]
    );

    if let Some(FrameLayer::Management(frame)) = Frame::new(payload).next_layer() {
        debug!(
            "Recieved a management frame: {:?} => {:?}",
            frame.source_address(),
            frame.receiver_address()
        );

        if let FrameSubtype::Management(ManagementSubtype::ProbeRequest) = frame.subtype() {
            match parse_probe_request(frame) {
                Err(e) => warn!(
                    "failed to parse Streetpass tag from management frame: {}",
                    e
                ),
                Ok(None) => debug!("management frame did not contain a Streetpass tag"),
                Ok(Some(tag)) => info!("Streetpass tag: {:?}", tag),
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
    flags: u16,
}

#[derive(Debug)]
struct StreetpassTag {
    services: Vec<StreetpassService>,
    console_id: u64,
}

impl StreetpassTag {
    fn parse(data: &[u8]) -> Result<Self> {
        let mut buf = data;

        let mut services = None;
        let mut console_id = None;

        while let [id, len, rest @ ..] = buf {
            let len = *len as usize;
            let (tag_data, rest) = rest.split_at(len);
            match id {
                0x11 => {
                    services = Some(
                        tag_data
                            .chunks(5)
                            .map(|service| {
                                debug!("service: {:02x?}", service);
                                StreetpassService {
                                    id: NetworkEndian::read_u24(&service[0..3]),
                                    flags: NetworkEndian::read_u16(&service[3..5]),
                                }
                            })
                            .collect(),
                    );
                }
                0xf0 if tag_data.len() == 8 => {
                    console_id = Some(NetworkEndian::read_u64(tag_data));
                }
                _ => debug!(
                    "Unknown Streetpass tag attribute {:02x} of length {}",
                    id, len
                ),
            };
            buf = rest;
        }

        Ok(Self {
            services: services.unwrap_or_default(),
            console_id: console_id
                .ok_or_else(|| anyhow!("Streetpass tag did not contain a console ID"))?,
        })
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
