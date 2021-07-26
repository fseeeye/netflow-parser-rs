use nom::bytes::complete::take;
use nom::combinator::peek;
use nom::number::complete::{be_u16, u8};

use crate::errors::ParseError;
use crate::layer::Layer;
use crate::layer_type::LayerType;
// use crate::{HeaderTrait, PayloadTrait};

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct EthernetHeader<'a> {
    pub dst_mac: &'a [u8],
    pub src_mac: &'a [u8],
    pub link_type: u16,
}

pub fn parse_ethernet_layer(input: &[u8]) -> nom::IResult<&[u8], (Layer, Option<LayerType>)> {
    let (input, header) = parse_header(input)?;
    let next = parse_payload(input, &header);
    let layer = Layer::Ethernet(header);

    Ok((
        input,
        (
            layer,
            next
        )
    ))
}

fn parse_header(input: &[u8]) -> nom::IResult<&[u8], EthernetHeader> {
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

fn parse_payload(
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

// impl<'a> HeaderTrait<'a> for EthernetHeader<'a> {
//     fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], EthernetHeader> {
//         let (input, dst_mac) = take(6usize)(input)?;
//         let (input, src_mac) = take(6usize)(input)?;
//         let (input, link_type) = be_u16(input)?;
//         Ok((
//             input,
//             EthernetHeader {
//                 dst_mac,
//                 src_mac,
//                 link_type,
//             },
//         ))
//     }

//     fn get_type(&self) -> LayerType{
//         return LayerType::Ethernet;
//     }
// }

// use super::eof::EofHeader;
// use super::ipv4::Ipv4Header;
// use super::ipv6::Ipv6Header;

// #[derive(Debug, PartialEq)]
// pub enum EthernetPayload<'a> {
//     Ipv4(Ipv4Header<'a>),
//     Ipv6(Ipv6Header<'a>),
//     Eof(EofHeader),
//     // Packet(Box<dyn PacketTrait<'a>>),
//     Unknown(&'a [u8]),
//     Error(EthernetPayloadError<'a>),
// }

// #[derive(Debug, PartialEq)]
// pub enum EthernetPayloadError<'a> {
//     Ipv4(&'a [u8]),
//     Ipv6(&'a [u8]),
//     Eof(&'a [u8]),
//     NomPeek(&'a [u8]),
// }

// impl<'a> PayloadTrait<'a> for EthernetPayload<'a> {
//     type Header = EthernetHeader<'a>;

//     fn parse(
//         input: &'a [u8],
//         _header: &EthernetHeader,
//     ) -> nom::IResult<&'a [u8], Self> {
//         let (input, version) = match peek(u8)(input) {
//             Ok((input, version)) => (input, version),
//             Err(nom::Err::Error((input, _))) => {
//                 return Ok((input, Self::Error(EthernetPayloadError::NomPeek(input))))
//             }
//             _ => return Ok((input, Self::Error(EthernetPayloadError::NomPeek(input)))),
//         };

//         match input.len() {
//             0 => match EofHeader::parse(input) {
//                 Ok((input, eof)) => Ok((input, Self::Eof(eof))),
//                 Err(_) => Ok((input, Self::Error(EthernetPayloadError::Eof(input)))),
//             },
//             _ => match version >> 4 {
//                 0x04 => match Ipv4Header::parse(input) {
//                     Ok((input, ipv4)) => {
//                         Ok((input, Self::Ipv4(ipv4)))
//                     },
//                     Err(_) => Ok((input, Self::Error(EthernetPayloadError::Ipv4(input)))),
//                 },
//                 0x06 => match Ipv6Header::parse(input) {
//                     Ok((input, ipv6)) => Ok((input, Self::Ipv6(ipv6))),
//                     Err(_) => Ok((input, Self::Error(EthernetPayloadError::Ipv6(input)))),
//                 },
//                 _ => Ok((input, Self::Unknown(input))),
//             },
//         }
//     }
// }