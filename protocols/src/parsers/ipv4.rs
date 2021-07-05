use nom::bits::bits;
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::{tag, take};
use nom::combinator::eof;
use nom::multi::count;
use nom::number::complete::{be_u16, be_u32, u8};
use nom::sequence::tuple;
use nom::IResult;

use crate::PacketTrait;

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

use super::tcp::TcpPacket;
use super::udp::UdpPacket;

#[derive(Debug, PartialEq)]
pub enum Ipv4Payload<'a> {
    Tcp(TcpPacket<'a>),
    Udp(UdpPacket<'a>),
    Unknown(&'a [u8]),
    Error(Ipv4PayloadError),
}

#[derive(Debug, PartialEq)]
pub enum Ipv4PayloadError {
    Tcp,
    Udp,
}

impl<'a> PacketTrait<'a> for Ipv4Packet<'a> {
    type Header = Ipv4Header<'a>;
    type Payload = Ipv4Payload<'a>;
    type PayloadError = Ipv4PayloadError;

    fn parse_header(input: &'a [u8]) -> nom::IResult<&'a [u8], Self::Header> {
        let (input, (version, header_length, diff_service, ecn)) =
            bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
                take_bits(4usize),
                take_bits(4usize),
                take_bits(6usize),
                take_bits(2usize),
            )))(input)?;
        let (input, total_length) = be_u16(input)?;
        let (input, id) = be_u16(input)?;
        let (input, (flags, fragment_offset)) = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
            tuple((take_bits(3usize), take_bits(13usize))),
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

    fn parse_payload(input: &'a [u8], _header: &Self::Header) -> nom::IResult<&'a [u8], Self::Payload> {
        match _header.protocol {
            // ref: https://www.ietf.org/rfc/rfc790.txt
            0x06 => match TcpPacket::parse(input) {
                Ok((input, tcp)) => Ok((input, Ipv4Payload::Tcp(tcp))),
                Err(_) => Ok((input, Ipv4Payload::Error(Ipv4PayloadError::Tcp))),
            },
            0x11 => match UdpPacket::parse(input) {
                Ok((input, udp)) => Ok((input, Ipv4Payload::Udp(udp))),
                Err(_) => Ok((input, Ipv4Payload::Error(Ipv4PayloadError::Udp))),
            },
            _ => Ok((input, Ipv4Payload::Unknown(input))),
        }
    }

    fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, header) = Self::parse_header(input)?;
        let (input, payload) = Self::parse_payload(input, &header)?;
        Ok((input, Self { header, payload }))
    }
}