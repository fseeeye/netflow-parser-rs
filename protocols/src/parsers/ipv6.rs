use nom::bits::bits;
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::take;
use nom::number::complete::{be_u16, u8};
use nom::sequence::tuple;

use crate::PacketTrait;

#[derive(Debug, PartialEq)]
pub struct Ipv6Packet<'a> {
    header: Ipv6Header<'a>,
    payload: Ipv6Payload<'a>,
}

#[derive(Debug, PartialEq)]
pub struct Ipv6Header<'a> {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_ip: &'a [u8],
    pub dst_ip: &'a [u8],
    pub extension_headers: Option<&'a [u8]>,
}

use super::tcp;
use super::udp;

#[derive(Debug, PartialEq)]
pub enum Ipv6Payload<'a> {
    Tcp(tcp::TcpPacket<'a>),
    Udp(udp::UdpPacket<'a>),
    Unknown(&'a [u8]),
    Error(Ipv6PayloadError<'a>),
}

#[derive(Debug, PartialEq)]
pub enum Ipv6PayloadError<'a> {
    Tcp(&'a [u8]),
    Udp(&'a [u8]),
    Eof(&'a [u8]),
    NomPeek(&'a [u8]),
}

impl<'a> PacketTrait<'a> for Ipv6Packet<'a> {
    type Header = Ipv6Header<'a>;
    type Payload = Ipv6Payload<'a>;
    type PayloadError = Ipv6PayloadError<'a>;

    fn parse_header(input: &'a [u8]) -> nom::IResult<&'a [u8], Self::Header> {
        let (input, (version, traffic_class, flow_label)) =
            bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
                take_bits(4usize),
                take_bits(8usize),
                take_bits(20usize),
            )))(input)?;
        let (input, payload_length) = be_u16(input)?;
        let (input, next_header) = u8(input)?;
        let (input, hop_limit) = u8(input)?;
        let (input, src_ip) = take(16usize)(input)?;
        let (input, dst_ip) = take(16usize)(input)?;
        let (input, extension_headers) = if payload_length > 40 {
            let (input, extension_headers) = take(payload_length - 40)(input)?;
            Ok((input, Some(extension_headers)))
        } else {
            Ok((input, None))
        }?;
        Ok((
            input,
            Ipv6Header {
                version,
                traffic_class,
                flow_label,
                payload_length,
                next_header,
                hop_limit,
                src_ip,
                dst_ip,
                extension_headers,
            },
        ))
    }

    fn parse_payload(
        _input: &'a [u8],
        _header: &Self::Header,
    ) -> nom::IResult<&'a [u8], Self::Payload> {
        unimplemented!();
    }

    fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, header) = Self::parse_header(input)?;
        let (input, payload) = Self::parse_payload(input, &header)?;
        Ok((input, Self { header, payload }))
    }
}
