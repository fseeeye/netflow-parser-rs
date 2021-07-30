use std::net::Ipv6Addr;
use std::convert::TryFrom;

use nom::bits::bits;
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::take;
use nom::number::complete::{be_u16, u8};
use nom::sequence::tuple;

// use crate::errors::ParseError;
use crate::layer_type::LayerType;
use crate::{Header, Layer};

// refs: https://en.wikipedia.org/wiki/IPv6_packet
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Ipv6Header<'a> {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
    pub extension_headers: Option<&'a [u8]>,
}

impl<'a> Header for Ipv6Header<'a> {
    fn get_payload(&self) -> Option<LayerType> {
        unimplemented!()
    }
}

pub fn parse_ipv6_layer(input: &[u8]) -> nom::IResult<&[u8], (Layer, Option<LayerType>)> {
    let (input, header) = parse_ipv6_header(input)?;
    let next = header.get_payload();
    let layer = Layer::Ipv6(header);

    Ok((
        input,
        (
            layer,
            next
        )
    ))
}

pub fn parse_ipv6_header(input: &[u8]) -> nom::IResult<&[u8], Ipv6Header> {
    let (input, (version, traffic_class, flow_label)) =
        bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
            take_bits(4usize),
            take_bits(8usize),
            take_bits(20usize),
        )))(input)?;
    let (input, payload_length) = be_u16(input)?;
    let (input, next_header) = u8(input)?;
    let (input, hop_limit) = u8(input)?;
    let (input, src_ip) = address6(input)?;
    let (input, dst_ip) = address6(input)?;
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

fn address6(input: &[u8]) -> nom::IResult<&[u8], Ipv6Addr> {
    let (input, ipv6) = take(16u8)(input)?;

    Ok((input, Ipv6Addr::from(<[u8; 16]>::try_from(ipv6).unwrap())))
}

// // refs: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
// fn parse_ipv6_payload(
//     _input: &[u8],
//     _header: &Ipv6Header,
// ) -> Option<LayerType> {
//     unimplemented!();
// }