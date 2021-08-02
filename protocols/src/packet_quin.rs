use std::default::Default;

use crate::layer::{ApplicationLayer, LinkLayer, NetworkLayer, TransportLayer};
use crate::LayerType;
use crate::errors::ParseError;
use crate::parsers::parse_ethernet_layer;

#[derive(Debug)]
pub enum QuinPacket<'a> {
    L1(L1Packet<'a>),
    L2(L2Packet<'a>),
    L3(L3Packet<'a>),
    L4(L4Packet<'a>),
    L5(L5Packet<'a>),
}

#[derive(Debug)]
pub struct L1Packet<'a> {
    pub error: Option<ParseError<'a>>,
}

#[derive(Debug)]
pub struct L2Packet<'a> {
    pub link_layer: LinkLayer,
    pub error: Option<ParseError<'a>>,
}

#[derive(Debug)]
pub struct L3Packet<'a> {
    pub link_layer: LinkLayer,
    pub net_layer: NetworkLayer<'a>,
    pub error: Option<ParseError<'a>>,
}

#[derive(Debug)]
pub struct L4Packet<'a> {
    pub link_layer: LinkLayer,
    pub net_layer: NetworkLayer<'a>,
    pub trans_layer: TransportLayer<'a>,
    pub error: Option<ParseError<'a>>,
}

#[derive(Debug)]
pub struct L5Packet<'a> {
    pub link_layer: LinkLayer,
    pub net_layer: NetworkLayer<'a>,
    pub trans_layer: TransportLayer<'a>,
    pub app_layer: ApplicationLayer<'a>,
    pub error: Option<ParseError<'a>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct QuinPacketOptions {
    stop: Option<LayerType>,
}

impl Default for QuinPacketOptions {
    fn default() -> Self {
        Self {
            stop: None,
        }
    }
}

#[inline]
pub fn parse_quin_enum_packet(input: &[u8], options: QuinPacketOptions) -> QuinPacket {
    parse_ethernet_layer(input, options)

    // // Tips: 不传递options / xxx_layer等参数，需要用到trait obj
    // let link_parser: Parser = Box::new(parse_ethernet_layer);

    // let (input, (link_layer, net_parser)) = match link_parser(input) {
    //     Ok(o) => o,
    //     Err(_e) => {
    //         return QuinPacket::L1(
    //             L1Packet {
    //                 remain: input,
    //                 error: Some(ParseError::ParsingHeader),
    //             }
    //         )
    //     }
    // };

    // let (input, (net_layer, trans_parser)) = match net_parser(input) {
    //     Ok(o) => o,
    //     Err(_e) => {
    //         return QuinPacket::L2(
    //             L2Packet {
    //                 link_layer,
    //                 remain: input,
    //                 error: Some(ParseError::ParsingHeader),
    //             }
    //         )
    //     }
    // };

    // let (input, (trans_layer, app_parser)) = match trans_parser(input) {
    //     Ok(o) => o,
    //     Err(_e) => {
    //         return QuinPacket::L3(
    //             L3Packet {
    //                 link_layer,
    //                 net_layer,
    //                 remain: input,
    //                 error: Some(ParseError::ParsingHeader),
    //             }
    //         )
    //     }
    // };

    // let (input, (app_layer, eof_parser)) = match app_parser(input) {
    //     Ok(o) => o,
    //     Err(_e) => {
    //         return QuinPacket::L4(
    //             L4Packet {
    //                 link_layer,
    //                 net_layer,
    //                 trans_layer,
    //                 remain: input,
    //                 error: Some(ParseError::ParsingHeader),
    //             }
    //         )
    //     }
    // };

    // // Q: 如何做循环
    // return QuinPacket::L5(
    //     L5Packet {
    //         link_layer,
    //         net_layer,
    //         trans_layer,
    //         app_layer,
    //         remain: input,
    //         error: Some(ParseError::ParsingHeader),
    //     }
    // )
}