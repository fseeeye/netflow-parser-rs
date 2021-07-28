use nom::bytes::complete::take;
use nom::number::complete::{be_u16};

use crate::Header;
use crate::errors::ParseError;
use crate::layer::Layer;
use crate::layer_type::LayerType;

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct EthernetHeader<'a> {
    pub dst_mac: &'a [u8],
    pub src_mac: &'a [u8],
    pub link_type: u16,
}

impl<'a> Header for EthernetHeader<'a> {
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
    let (input, dst_mac) = take(6usize)(input)?;
    let (input, src_mac) = take(6usize)(input)?;
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

// // refs: https://en.wikipedia.org/wiki/EtherType
// pub fn parse_ethernet_payload(
//     input: &[u8],
//     _header: &EthernetHeader,
// ) -> Option<LayerType> {
//     match input.len() {
//         0 => Some(LayerType::Eof),
//         _ => match _header.link_type {
//             0x0800 => Some(LayerType::Ipv4),
//             0x86DD => Some(LayerType::Ipv6),
//             _ => Some(LayerType::Error(ParseError::UnknownPayload)),
//         },
//     }
// }
