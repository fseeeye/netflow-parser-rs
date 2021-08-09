use nom::bytes::complete::take;
use nom::combinator::peek;
use nom::number::complete::{be_u16, u8};

use std::convert::TryFrom;

use crate::errors::ParseError;
use crate::layer::LinkLayer;
use crate::packet_level::{L1Packet, L2Packet};
use crate::packet_quin::{QuinPacket, QuinPacketOptions};
use crate::{Layer, LayerType};

use super::{parse_ipv4_layer, parse_ipv6_layer, parse_l2_eof_layer};

pub fn parse_ethernet_fatlayer(input: &[u8]) -> nom::IResult<&[u8], (Layer, Option<LayerType>)> {
    let (input, header) = parse_ethernet_header(input)?;
    let next = parse_ethernet_payload(input, &header);
    let layer = Layer::Ethernet(header);

    Ok((input, (layer, next)))
}

fn parse_ethernet_payload(input: &[u8], _header: &EthernetHeader) -> Option<LayerType> {
    let (input, version) = match peek(u8)(input) {
        Ok((input, version)) => (input, version),
        Err(nom::Err::Error((_, _))) => return Some(LayerType::Error(ParseError::ParsingPayload)),
        _ => return Some(LayerType::Error(ParseError::ParsingPayload)),
    };

    match input.len() {
        0 => Some(LayerType::Eof),
        _ => match version >> 4 {
            0x04 => Some(LayerType::Ipv4),
            0x06 => Some(LayerType::Ipv6),
            _ => Some(LayerType::Error(ParseError::UnknownPayload)),
        },
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct MacAddress(pub [u8; 6]);

fn mac_address(input: &[u8]) -> nom::IResult<&[u8], MacAddress> {
    let (input, mac) = take(6usize)(input)?;

    Ok((input, MacAddress(<[u8; 6]>::try_from(mac).unwrap()))) // Warning: unwarp unchecked
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct EthernetHeader {
    pub dst_mac: MacAddress,
    pub src_mac: MacAddress,
    pub link_type: u16,
}

pub fn parse_ethernet_header(input: &[u8]) -> nom::IResult<&[u8], EthernetHeader> {
    let (input, dst_mac) = mac_address(input)?;
    let (input, src_mac) = mac_address(input)?;
    let (input, link_type) = be_u16(input)?;

    Ok((
        input,
        EthernetHeader {
            dst_mac,
            src_mac,
            link_type,
        },
    ))
}

pub(crate) fn parse_ethernet_layer(input: &[u8], options: QuinPacketOptions) -> QuinPacket {
    let current_layertype = LayerType::Ethernet;

    let (input, eth_header) = match parse_ethernet_header(input) {
        Ok(o) => o,
        Err(_e) => {
            return QuinPacket::L1(L1Packet {
                error: Some(ParseError::ParsingHeader),
                remain: input,
            })
        }
    };

    if Some(current_layertype) == options.stop {
        let link_layer = LinkLayer::Ethernet(eth_header);
        return QuinPacket::L2(L2Packet {
            link_layer,
            error: None,
            remain: input,
        });
    }

    if input.len() == 0 {
        let link_layer = LinkLayer::Ethernet(eth_header);
        return parse_l2_eof_layer(input, link_layer, options);
    }
    // refs: https://en.wikipedia.org/wiki/EtherType
    match eth_header.link_type {
        0x0800 => {
            let link_layer = LinkLayer::Ethernet(eth_header);
            parse_ipv4_layer(input, link_layer, options)
        }
        0x86DD => {
            let link_layer = LinkLayer::Ethernet(eth_header);
            parse_ipv6_layer(input, link_layer, options)
        }
        _ => {
            let link_layer = LinkLayer::Ethernet(eth_header);
            return QuinPacket::L2(L2Packet {
                link_layer,
                error: Some(ParseError::UnknownPayload),
                remain: input,
            });
        }
    }
}
