use std::convert::TryFrom;
use std::net::Ipv4Addr;

use nom::bits::bits;
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::take;
use nom::number::complete::{be_u16, u8};
use nom::sequence::tuple;

use crate::errors::ParseError;
use crate::layer::{LinkLayer, NetworkLayer};
use crate::packet_level::{L2Packet, L3Packet};
use crate::packet_quin::{QuinPacket, QuinPacketOptions};
use crate::{LayerType};

use super::{parse_l3_eof_layer, parse_tcp_layer, parse_udp_layer};

#[derive(Debug, PartialEq, Clone)]
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
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub options: Option<&'a [u8]>,
}

pub fn parse_ipv4_header(input: &[u8]) -> nom::IResult<&[u8], Ipv4Header> {
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
    let (input, src_ip) = address4(input)?;
    let (input, dst_ip) = address4(input)?;
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

fn address4(input: &[u8]) -> nom::IResult<&[u8], Ipv4Addr> {
    let (input, ipv4_addr) = take(4u8)(input)?;

    Ok((
        input,
        Ipv4Addr::from(<[u8; 4]>::try_from(ipv4_addr).unwrap()),
    ))
}

pub(crate) fn parse_ipv4_layer(
    input: &[u8],
    link_layer: LinkLayer,
    options: QuinPacketOptions,
) -> QuinPacket {
    let current_layertype = LayerType::Ipv4;

    let (input, ipv4_header) = match parse_ipv4_header(input) {
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
        let net_layer = NetworkLayer::Ipv4(ipv4_header);
        return QuinPacket::L3(L3Packet {
            link_layer,
            net_layer,
            error: None,
            remain: input,
        });
    }

    if input.len() == 0 {
        let net_layer = NetworkLayer::Ipv4(ipv4_header);
        return parse_l3_eof_layer(input, link_layer, net_layer, options);
    }
    // ref: https://www.ietf.org/rfc/rfc790.txt
    match ipv4_header.protocol {
        0x06 => {
            let net_layer = NetworkLayer::Ipv4(ipv4_header);
            parse_tcp_layer(input, link_layer, net_layer, options)
        }
        0x11 => {
            let net_layer = NetworkLayer::Ipv4(ipv4_header);
            parse_udp_layer(input, link_layer, net_layer, options)
        }
        _ => {
            let net_layer = NetworkLayer::Ipv4(ipv4_header);
            return QuinPacket::L3(L3Packet {
                link_layer,
                net_layer,
                error: Some(ParseError::UnknownPayload),
                remain: input,
            });
        }
    }
}
