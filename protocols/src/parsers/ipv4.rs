use nom::bits::bits;
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::{tag, take};
use nom::combinator::eof;
use nom::multi::count;
use nom::number::complete::{be_u16, be_u32, u8};
use nom::sequence::tuple;
use nom::IResult;

use crate::traits::PacketTrait; // changed
use super::parser_context::ParserContext; // added

#[derive(Debug, PartialEq)]
pub struct Ipv4<'a> {
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

use super::{tcp, udp}; // changed

#[derive(Debug, PartialEq)]
pub enum Ipv4PayloadError {
    Tcp,
    Udp,
}

#[derive(Debug, PartialEq)]
pub enum Ipv4Payload<'a> {
    Tcp(tcp::TcpPacket<'a>),
    Udp(udp::UdpPacket<'a>),
    Unknown(&'a [u8]),
    Error(Ipv4PayloadError),
}

#[derive(Debug, PartialEq)]
pub struct Ipv4Packet<'a> {
    header: Ipv4<'a>,
    payload: Ipv4Payload<'a>,
}

impl<'a> PacketTrait<'a> for Ipv4Packet<'a> {
    type Header = Ipv4<'a>;
    type Payload = Ipv4Payload<'a>;
    type PayloadError = Ipv4PayloadError;

    fn parse_header(input: &'a [u8], _context: &mut ParserContext) -> nom::IResult<&'a [u8], Self::Header> {
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
            Self::Header {
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

    fn parse_payload(input: &'a [u8], header: &Self::Header, context: &mut ParserContext) -> nom::IResult<&'a [u8], Self::Payload> {
        use super::tcp::TcpPacket;

        match header.protocol {
            0x06 => match TcpPacket::parse(input, context) {
                Ok((input, tcp)) => Ok((input, Self::Payload::Tcp(tcp))),
                Err(_) => Ok((input, Self::Payload::Error(Self::PayloadError::Tcp))),
            },
            0x11 => Ok((input, Self::Payload::Unknown(input))),
            _ => Ok((input, Self::Payload::Unknown(input))),
        }
    }

    fn parse(input: &'a [u8], context: &mut ParserContext) -> nom::IResult<&'a [u8], Self> {
        let (input, header) = Self::parse_header(input, context)?;
        let (input, payload) = Self::parse_payload(input, &header, context)?;
        Ok((input, Self { header, payload }))
    }
}
