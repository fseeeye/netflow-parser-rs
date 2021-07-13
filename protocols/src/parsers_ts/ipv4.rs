#[allow(unused)]
use nom::bits::bits;
#[allow(unused)]
use nom::bits::complete::take as take_bits;
#[allow(unused)]
use nom::bytes::complete::{tag, take};
#[allow(unused)]
use nom::combinator::{eof, map, peek};
#[allow(unused)]
use nom::error::{ErrorKind, Error};
#[allow(unused)]
use nom::multi::count;
#[allow(unused)]
use nom::number::complete::{be_u16, be_u32, u8};
#[allow(unused)]
use nom::sequence::tuple;
#[allow(unused)]
use nom::IResult;

use crate::PacketTrait;

#[derive(Debug, PartialEq)]
pub struct Ipv4Packet<'a> {
    pub ipv4_header: Ipv4Header<'a>,
    pub ipv4_payload: Ipv4Payload<'a>,
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

use super::tcp::TcpPacket;
use super::udp::UdpPacket;
use super::eof::EofPacket;

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
    type Header = Ipv4Header<'a>;
    type Payload = Ipv4Payload<'a>;
    type PayloadError = Ipv4PayloadError<'a>;

    fn parse_header(input: &'a [u8]) -> nom::IResult<&'a [u8], Self::Header> {
        let (input, (version, header_length, diff_service, ecn)) = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
            tuple((take_bits(4usize), take_bits(4usize), take_bits(6usize), take_bits(2usize)))
        )(input)?;
        let (input, total_length) = be_u16(input)?;
        let (input, id) = be_u16(input)?;
        let (input, (flags, fragment_offset)) = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
            tuple((take_bits(3usize), take_bits(13usize)))
        )(input)?;
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
                version, header_length, diff_service, ecn,
                total_length,
                id,
                flags, fragment_offset,
                ttl,
                protocol,
                checksum,
                src_ip,
                dst_ip,
                options
            }
        ))
    }

    fn parse_payload(
        input: &'a [u8], 
        _header: &Self::Header
    ) -> nom::IResult<&'a [u8], Self::Payload> {
        match input.len() {
            0 => match EofPacket::parse(input) {
                Ok((input, eof)) => Ok((input, Ipv4Payload::Eof(eof))),
                Err(_) => Ok((input, Ipv4Payload::Error(Ipv4PayloadError::Eof(input)))),
            },
            _ => match _header.protocol {
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

    fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, ipv4_header) = Self::parse_header(input)?;
        let (input, ipv4_payload) = Self::parse_payload(input, &ipv4_header)?;
        Ok((input, Self { ipv4_header, ipv4_payload }))
    }            
}