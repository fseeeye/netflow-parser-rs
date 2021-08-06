use std::default::Default;

use crate::packet_level::{L1Packet, L2Packet, L3Packet, L4Packet, L5Packet};
use crate::parsers::parse_ethernet_layer;
use crate::LayerType;

/// QuinPacket是一种层级结构的packet，使用示例如下：
/// ```
/// use parsing_rs::*;
/// 
/// match parse_quin_packet(input, QuinPacketOptions::default()) {
///     QuinPacket::L1(l1) => {
///         println!("l1 packet: {:?}", l1);
///     }
///     QuinPacket::L2(l2) => {
///         println!("l2 packet: {:?}", l2);
///         println!("l2 dst mac: {:?}", l2.get_dst_mac());
///         println!("l2 src mac: {:?}", l2.get_src_mac());
///     }
///     QuinPacket::L3(l3) => {
///         println!("l3 packet: {:?}", l3);
///         println!("l3 dst ip: {:?}", l3.get_dst_ip());
///         println!("l3 src ip: {:?}", l3.get_src_ip());
///     }
///     QuinPacket::L4(l4) => {
///         println!("l4 packet: {:?}", l4);
///         println!("l4 dst port: {:?}", l4.get_dst_port());
///         println!("l4 src port: {:?}", l4.get_src_port());
///     }
///     QuinPacket::L5(l5) => {
///         println!("l5 packet: {:?}", l5);
///     }
/// };
/// ```
#[derive(Debug)]
pub enum QuinPacket<'a> {
    L1(L1Packet<'a>),
    L2(L2Packet<'a>),
    L3(L3Packet<'a>),
    L4(L4Packet<'a>),
    L5(L5Packet<'a>),
}

/// QuinPacketOptions为QuinPacket解析选项，提供多种解析特性。
/// 支持default：
/// ```
/// parse_quin_packet(input, QuinPacketOptions::default())
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct QuinPacketOptions {
    pub stop: Option<LayerType>,
}

impl Default for QuinPacketOptions {
    fn default() -> Self {
        Self { stop: None }
    }
}

/// 解析u8流为QuinPacket的函数
/// 硬编码默认第一层是link的Ethernet。
pub fn parse_quin_packet(input: &[u8], options: QuinPacketOptions) -> QuinPacket {
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
