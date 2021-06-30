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
pub struct Ipv6<'a> {
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

use super::{tcp, udp}; // changed

#[derive(Debug, PartialEq)]
pub enum Ipv6PayloadError {
    Tcp,
    Udp,
}

#[derive(Debug, PartialEq)]
pub enum Ipv6Payload<'a> {
    Tcp(tcp::TcpPacket<'a>),
    Udp(udp::UdpPacket<'a>),
    Unknown(&'a [u8]),
    Error(Ipv6PayloadError),
}

#[derive(Debug, PartialEq)]
pub struct Ipv6Packet<'a> {
    header: Ipv6<'a>,
    payload: Ipv6Payload<'a>,
}

impl<'a> PacketTrait<'a> for Ipv6Packet<'a> {
    type Header = Ipv6<'a>;
    type Payload = Ipv6Payload<'a>;
	type PayloadError = Ipv6PayloadError;
	
	fn parse_header(input: &'a [u8], _context: &mut ParserContext) -> IResult<&'a [u8], Self::Header> {
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
            Self::Header {
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

	fn parse_payload(input: &'a [u8], _header: &Self::Header, context: &mut ParserContext) -> IResult<&'a [u8], Self::Payload> {
        unimplemented!();
    }
	fn parse(input: &'a [u8], context: &mut ParserContext) -> nom::IResult<&'a [u8], Self> {
        unimplemented!();
    }
}
