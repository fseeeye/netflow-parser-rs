use nom::bits::bits;
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::{tag, take};
use nom::combinator::{eof, peek, map};
use nom::multi::count;
use nom::number::complete::{be_u16, be_u32, u8};
use nom::sequence::tuple;
use nom::IResult;

use crate::traits::PacketTrait; // changed
use super::parser_context::ParserContext; // added

#[derive(Debug, PartialEq)]
pub struct Ethernet<'a> {
    pub dst_mac: &'a [u8],
    pub src_mac: &'a [u8],
    pub link_type: u16,
}

// changed
use super::ipv4;
use super::ipv6;
#[derive(Debug, PartialEq)]
pub enum EthernetPayloadError {
    Ipv4,
    Ipv6,
}

#[derive(Debug, PartialEq)]
pub enum EthernetPayload<'a> {
    Ipv4(ipv4::Ipv4Packet<'a>),
    Ipv6(ipv6::Ipv6Packet<'a>),
    Unknown(&'a [u8]),
    Error(EthernetPayloadError),
}

#[derive(Debug, PartialEq)]
pub struct EthernetPacket<'a> {
    pub header: Ethernet<'a>,
    pub payload: EthernetPayload<'a>,
}

impl<'a> PacketTrait<'a> for EthernetPacket<'a> {
    type Header = Ethernet<'a>;
    type Payload = EthernetPayload<'a>;
    type PayloadError = EthernetPayloadError;

    // added
    fn parse_header(input: &'a [u8], _context: &mut ParserContext) -> IResult<&'a [u8], Self::Header> {
        let (input, dst_mac) = take(6usize)(input)?;
        let (input, src_mac) = take(6usize)(input)?;
        let (input, link_type) = be_u16(input)?;
        Ok((
            input,
            Self::Header {
                dst_mac,
                src_mac,
                link_type,
            },
        ))
    }

    fn parse_payload(input: &'a [u8], _header: &Self::Header, context: &mut ParserContext) -> IResult<&'a [u8], Self::Payload> {
        use super::ipv4::Ipv4Packet;
        let mut parser =
            map::<_, _, _, nom::error::Error<&[u8]>, _, _>(peek(u8), |version: u8| version >> 4);
        match parser(input) {
            Ok((input, version)) => match version {
                0x04 => match Ipv4Packet::parse(input, context) { // changed
                    Ok((input, ipv4)) => Ok((input, Self::Payload::Ipv4(ipv4))), // changed
                    Err(_) => Ok((input, Self::Payload::Error(Self::PayloadError::Ipv4))), // changed
                },
                _ => Ok((input, Self::Payload::Unknown(input))), // changed
            },
            Err(_) => Ok((input, Self::Payload::Unknown(input))), // changed
        }
    }

    fn parse(input: &'a [u8], context: &mut ParserContext) -> nom::IResult<&'a [u8], Self> {
        let (input, header) = Self::parse_header(input, context)?;
        let (input, payload) = Self::parse_payload(input, &header, context)?; // changed
        Ok((input, Self { header, payload }))
    }
}
