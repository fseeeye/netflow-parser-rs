use nom::bytes::complete::take;
use nom::number::complete::{be_u16};

use std::convert::TryFrom;

use crate::Header;
use crate::errors::ParseError;
use crate::layer::Layer;
use crate::layer_type::LayerType;

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

impl Header for EthernetHeader {
    // refs: https://en.wikipedia.org/wiki/EtherType
    fn get_payload(&self) -> Option<LayerType> {
        match self.link_type {
            0x0800 => Some(LayerType::Ipv4),
            0x86DD => Some(LayerType::Ipv6),
            _ => Some(LayerType::Error(ParseError::UnknownPayload)),
        }
    }
}

pub fn parse_ethernet_layer(input: &[u8]) -> nom::IResult<&[u8], (Layer, Option<LayerType>)> {
    let (input, header) = parse_ethernet_header(input)?;
    let next = header.get_payload();
    let layer = Layer::Ethernet(header);

    Ok((
        input,
        (
            layer,
            next
        )
    ))
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
