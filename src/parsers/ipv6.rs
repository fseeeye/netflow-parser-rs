use std::convert::TryFrom;
use std::net::Ipv6Addr;

use nom::bits::bits;
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::take;
use nom::number::complete::{be_u16, u8};
use nom::sequence::tuple;

use super::{parse_l3_eof_layer, parse_tcp_layer, parse_udp_layer};
use crate::errors::ParseError;
use crate::layer::{LinkLayer, NetworkLayer};
use crate::packet_level::{L2Packet, L3Packet};
use crate::packet_quin::{QuinPacket, QuinPacketOptions};
use crate::LayerType;

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

pub(crate) fn parse_ipv6_layer(
    input: &[u8],
    link_layer: LinkLayer,
    options: QuinPacketOptions,
) -> QuinPacket {
    let current_layertype = LayerType::Ipv6;

    let (input, ipv6_header) = match parse_ipv6_header(input) {
        Ok(o) => o,
        Err(_e) => {
            return QuinPacket::L2(L2Packet {
                link_layer,
                error: Some(ParseError::ParsingHeader),
                remain: input,
            })
        }
    };

    if Some(current_layertype) == options.stop {
        let net_layer = NetworkLayer::Ipv6(ipv6_header);
        return QuinPacket::L3(L3Packet {
            link_layer,
            net_layer,
            error: None,
            remain: input,
        });
    }

    if input.len() == 0 {
        let net_layer = NetworkLayer::Ipv6(ipv6_header);
        return parse_l3_eof_layer(input, link_layer, net_layer, options);
    }
    // refs: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    match ipv6_header.next_header {
        0x06 => {
            let net_layer = NetworkLayer::Ipv6(ipv6_header);
            parse_tcp_layer(input, link_layer, net_layer, options)
        }
        0x11 => {
            let net_layer = NetworkLayer::Ipv6(ipv6_header);
            parse_udp_layer(input, link_layer, net_layer, options)
        }
        _ => {
            let net_layer = NetworkLayer::Ipv6(ipv6_header);
            return QuinPacket::L3(L3Packet {
                link_layer,
                net_layer,
                error: Some(ParseError::UnknownPayload),
                remain: input,
            });
        }
    }
}
