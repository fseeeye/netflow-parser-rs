use nom::number::complete::be_u16;

use crate::errors::ParseError;
use crate::field_type::*;
use crate::layer::LinkLayer;
use crate::packet::{L1Packet, L2Packet, QuinPacket, QuinPacketOptions};
use crate::protocol::LinkProtocol;
use crate::ProtocolType;

use super::{parse_ipv4_layer, parse_ipv6_layer, parse_l2_eof_layer, parse_goose_layer, parse_vlan_layer};

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

pub fn parse_ethernet_layer<'a>(input: &'a [u8], options: &QuinPacketOptions) -> QuinPacket<'a> {
    let current_prototype = ProtocolType::Link(LinkProtocol::Ethernet);
    let input_size = input.len();

    let (input, eth_header) = match parse_ethernet_header(input) {
        Ok(o) => o,
        Err(_e) => {
            return QuinPacket::L1(L1Packet {
                error: Some(ParseError::ParsingHeader{
                    protocol: current_prototype,
                    offset: input_size - input.len()
                }),
                remain: input,
            })
        }
    };

    if Some(current_prototype) == options.stop {
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
        0x0800 => { // IPv4
            let link_layer = LinkLayer::Ethernet(eth_header);
            parse_ipv4_layer(input, link_layer, options)
        }
        0x8100 => { // Virtual LAN tagged frame
            let link_layer = LinkLayer::Ethernet(eth_header);
            parse_vlan_layer(input, link_layer, options)
        }
        0x86DD => { // IPv6
            let link_layer = LinkLayer::Ethernet(eth_header);
            parse_ipv6_layer(input, link_layer, options)
        }
        0x88B8 => { // GOOSE (Generic Object Oriented Substation event)
            let link_layer = LinkLayer::Ethernet(eth_header);
            parse_goose_layer(input, link_layer, options)
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
