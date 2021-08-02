// use nom::combinator::eof;

use crate::errors::ParseError;
use crate::layer::{LinkLayer, NetworkLayer, TransportLayer, ApplicationLayer};
use crate::packet_quin::{L2Packet, L3Packet, L4Packet, L5Packet, QuinPacket, QuinPacketOptions};

// #[derive(Debug, PartialEq, Clone)]
// pub struct EofHeader {
//     pub end: bool,
// }

// pub(crate) fn parse_eof_header(input: &[u8]) -> nom::IResult<&[u8], EofHeader> {
//     match eof::<_, ()>(input) {
//         Ok((_input, _nullstr)) => Ok((input, EofHeader{ end: true })),
//         Err(_e) => Ok((input, EofHeader{ end: false })),
//     }
// }

pub(crate) fn parse_l2_eof_layer<'a>(input: &'a [u8], link_layer: LinkLayer, _options: QuinPacketOptions) -> QuinPacket<'a> {
    if input.len() == 0 {
        return QuinPacket::L2(
            L2Packet {
                link_layer,
                error: None,
            }
        )
    } else {
        return QuinPacket::L2(
            L2Packet {
                link_layer,
                error: Some(ParseError::NotEndPayload(input)),
            }
        )
    }
}

pub(crate) fn parse_l3_eof_layer<'a>(input: &'a [u8], link_layer: LinkLayer, net_layer: NetworkLayer<'a>, _options: QuinPacketOptions) -> QuinPacket<'a> {
    if input.len() == 0 {
        return QuinPacket::L3(
            L3Packet {
                link_layer,
                net_layer,
                error: None,
            }
        )
    } else {
        return QuinPacket::L3(
            L3Packet {
                link_layer,
                net_layer,
                error: Some(ParseError::NotEndPayload(input)),
            }
        )
    }
}

pub(crate) fn parse_l4_eof_layer<'a>(input: &'a [u8], link_layer: LinkLayer, net_layer: NetworkLayer<'a>, trans_layer: TransportLayer<'a>, _options: QuinPacketOptions) -> QuinPacket<'a> {
    if input.len() == 0 {
        return QuinPacket::L4(
            L4Packet {
                link_layer,
                net_layer,
                trans_layer,
                error: None,
            }
        )
    } else {
        return QuinPacket::L4(
            L4Packet {
                link_layer,
                net_layer,
                trans_layer,
                error: Some(ParseError::NotEndPayload(input)),
            }
        )
    }
}

pub(crate) fn parse_l5_eof_layer<'a>(input: &'a [u8], link_layer: LinkLayer, net_layer: NetworkLayer<'a>, trans_layer: TransportLayer<'a>, app_layer: ApplicationLayer<'a>, _options: QuinPacketOptions) -> QuinPacket<'a> {
    if input.len() == 0 {
        return QuinPacket::L5(
            L5Packet {
                link_layer,
                net_layer,
                trans_layer,
                app_layer,
                error: None,
            }
        )
    } else {
        return QuinPacket::L5(
            L5Packet {
                link_layer,
                net_layer,
                trans_layer,
                app_layer,
                error: Some(ParseError::NotEndPayload(input)),
            }
        )
    }
}