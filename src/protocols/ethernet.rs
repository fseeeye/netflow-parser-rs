use nom::bits::bits;
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::{tag, take};
use nom::combinator::eof;
use nom::combinator::map;
use nom::combinator::peek;
use nom::multi::count;
use nom::number::complete::{be_u16, be_u32, u8};
use nom::IResult;

use super::traits::PacketTrait;

#[derive(Debug, PartialEq)]
pub struct Ethernet<'a> {
    pub dst_mac: &'a [u8],
    pub src_mac: &'a [u8],
    pub link_type: u16,
}

pub fn parse_ethernet<'a>(input: &'a [u8]) -> IResult<&'a [u8], Ethernet<'a>> {
    let (input, dst_mac) = take(6usize)(input)?;
    let (input, src_mac) = take(6usize)(input)?;
    let (input, link_type) = be_u16(input)?;
    Ok((
        input,
        Ethernet {
            dst_mac,
            src_mac,
            link_type,
        },
    ))
}

#[derive(Debug, PartialEq)]
pub struct Packet<'a> {
    pub header: Ethernet<'a>,
    pub payload: L2Payload<'a>,
}

use super::ipv4;
use super::ipv6;
use super::payload::{l2, L2Payload};

fn parse_ethernet_payload<'a>(input: &'a [u8], _header: &Ethernet) -> (&'a [u8], L2Payload<'a>) {
    use super::ipv4::parse_ipv4_packet;
    let mut parser =
        map::<_, _, _, nom::error::Error<&[u8]>, _, _>(peek(u8), |version: u8| version >> 4);
    match parser(input) {
        Ok((input, version)) => match version {
            0x04 => match parse_ipv4_packet(input) {
                Ok((input, ipv4)) => (input, L2Payload::Ipv4(ipv4)),
                Err(_) => (input, L2Payload::Error(l2::Error::Ipv4)),
            },
            _ => (input, L2Payload::Unknown(input)),
        },
        Err(_) => (input, L2Payload::Unknown(input)),
    }
}

impl<'a> PacketTrait<'a> for Packet<'a> {
    type Header = Ethernet<'a>;
    type Payload = L2Payload<'a>;

    fn parse_payload(input: &'a [u8], _header: &Self::Header) -> (&'a [u8], L2Payload<'a>) {
        use super::ipv4::parse_ipv4_packet;
        let mut parser =
            map::<_, _, _, nom::error::Error<&[u8]>, _, _>(peek(u8), |version: u8| version >> 4);
        match parser(input) {
            Ok((input, version)) => match version {
                0x04 => match parse_ipv4_packet(input) {
                    Ok((input, ipv4)) => (input, L2Payload::Ipv4(ipv4)),
                    Err(_) => (input, L2Payload::Error(l2::Error::Ipv4)),
                },
                _ => (input, L2Payload::Unknown(input)),
            },
            Err(_) => (input, L2Payload::Unknown(input)),
        }
    }

    fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, header) = parse_ethernet(input)?;
        let (input, payload) = Self::parse_payload(input, &header);
        Ok((input, Packet { header, payload }))
    }
}

// pub fn parse_ipv4_packet<'a>(input: &'a [u8]) -> nom::IResult<&[u8], Packet<'a>> {
//     let (input, header) = parse_ipv4(input)?;
//     let (input, payload) = parse_ipv4_payload(input, &header);
//     Ok((input, Packet { header, payload }))
// }
