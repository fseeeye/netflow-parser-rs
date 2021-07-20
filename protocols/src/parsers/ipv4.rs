use nom::bits::bits;
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::take;
use nom::number::complete::{be_u16, be_u32, u8};
use nom::sequence::tuple;

use crate::types::LayerType;
use crate::{PacketTrait, HeaderTrait, PayloadTrait};

#[derive(Debug, PartialEq)]
pub struct Ipv4Packet<'a> {
    header: Ipv4Header<'a>,
    payload: Ipv4Payload<'a>,
}

#[derive(Debug, PartialEq)]
pub struct Ipv4Header<'a> {
    pub version: u8,
    pub header_length: u8,
    pub diff_service: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub id: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub options: Option<&'a [u8]>,
}

use super::eof::EofPacket;
use super::tcp::TcpPacket;
use super::udp::UdpPacket;

#[derive(Debug, PartialEq)]
pub enum Ipv4Payload<'a> {
    Tcp(TcpPacket<'a>),
    Udp(UdpPacket<'a>),
    Eof(EofPacket<'a>),
    Unknown(&'a [u8]),
    Error(Ipv4PayloadError<'a>),
}

#[derive(Debug, PartialEq)]
pub enum Ipv4PayloadError<'a> {
    Tcp(&'a [u8]),
    Udp(&'a [u8]),
    Eof(&'a [u8]),
    NomPeek(&'a [u8]),
}

impl<'a> PacketTrait<'a> for Ipv4Packet<'a> {
    fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, header) = Ipv4Header::parse(input)?;
        let (input, payload) = Ipv4Payload::parse(input, &header)?;
        Ok((input, Self { header, payload }))
    }
}

impl<'a> HeaderTrait<'a> for Ipv4Header<'a> {
    fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, (version, header_length, diff_service, ecn)) =
            bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
                take_bits(4usize),
                take_bits(4usize),
                take_bits(6usize),
                take_bits(2usize),
            )))(input)?;
        let (input, total_length) = be_u16(input)?;
        let (input, id) = be_u16(input)?;
        let (input, (flags, fragment_offset)) =
            bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
                take_bits(3usize),
                take_bits(13usize),
            )))(input)?;
        let (input, ttl) = u8(input)?;
        let (input, protocol) = u8(input)?;
        let (input, checksum) = be_u16(input)?;
        let (input, src_ip) = be_u32(input)?;
        let (input, dst_ip) = be_u32(input)?;
        let (input, options) = if (header_length * 4) > 20 {
            let (input, options) = take(header_length * 4 - 20)(input)?;
            Ok((input, Some(options)))
        } else {
            Ok((input, None))
        }?;
        Ok((
            input,
            Ipv4Header {
                version,
                header_length,
                diff_service,
                ecn,
                total_length,
                id,
                flags,
                fragment_offset,
                ttl,
                protocol,
                checksum,
                src_ip,
                dst_ip,
                options,
            },
        ))
    }

    fn get_type(&self) -> LayerType {
        return LayerType::Ipv4;
    }
}

impl<'a> PayloadTrait<'a> for Ipv4Payload<'a> {
    type Header = Ipv4Header<'a>;

    fn parse(
        input: &'a [u8],
        _header: &Self::Header,
    ) -> nom::IResult<&'a [u8], Self> {
        match input.len() {
            0 => match EofPacket::parse(input) {
                Ok((input, eof)) => Ok((input, Ipv4Payload::Eof(eof))),
                Err(_) => Ok((input, Ipv4Payload::Error(Ipv4PayloadError::Eof(input)))),
            },
            _ => match _header.protocol {
                // ref: https://www.ietf.org/rfc/rfc790.txt
                0x06 => match TcpPacket::parse(input) {
                    Ok((input, tcp)) => Ok((input, Ipv4Payload::Tcp(tcp))),
                    Err(_) => Ok((input, Ipv4Payload::Error(Ipv4PayloadError::Tcp(input)))),
                },
                0x11 => match UdpPacket::parse(input) {
                    Ok((input, udp)) => Ok((input, Ipv4Payload::Udp(udp))),
                    Err(_) => Ok((input, Ipv4Payload::Error(Ipv4PayloadError::Udp(input)))),
                },
                _ => Ok((input, Ipv4Payload::Unknown(input))),
            },
        }
    }
}