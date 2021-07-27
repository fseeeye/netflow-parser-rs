use nom::bytes::complete::take;
use nom::combinator::peek;
use nom::number::complete::{be_u16, u8};

use crate::errors::ParseError;
use crate::layer::Layer;
use crate::layer_type::LayerType;

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct EthernetHeader<'a> {
    pub dst_mac: &'a [u8],
    pub src_mac: &'a [u8],
    pub link_type: u16,
}

pub fn parse_ethernet_layer(input: &[u8]) -> nom::IResult<&[u8], (Layer, Option<LayerType>)> {
    let (input, header) = parse_ethernet_header(input)?;
    let next = parse_ethernet_payload(input, &header);
    let layer = Layer::Ethernet(header);

    Ok((
        input,
        (
            layer,
            next
        )
    ))
}

fn parse_ethernet_header(input: &[u8]) -> nom::IResult<&[u8], EthernetHeader> {
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

fn parse_ethernet_payload(
    input: &[u8],
    _header: &EthernetHeader,
) -> Option<LayerType> {
    let (input, version) = match peek(u8)(input) {
        Ok((input, version)) => (input, version),
        Err(nom::Err::Error((_, _))) => {
            return Some(LayerType::Error(ParseError::ParsingPayload))
        },
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
