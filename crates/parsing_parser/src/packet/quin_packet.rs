use std::default::Default;

use super::level::PhyLevel;
use super::level_packet::{L1Packet, L2Packet, L3Packet, L4Packet, L5Packet};
use crate::parsers::parse_ethernet_layer;
use crate::ProtocolType;

/// QuinPacket是由 Level1 - Level5 Packet 构成的枚举结构，使用示例如下：
/// ```
/// use parsing_parser::*;
///
/// let input = &[1,2,3,4,5,6];
/// match QuinPacket::parse_from_stream(input, &QuinPacketOptions::default()) {
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

impl<'a> QuinPacket<'a> {
    /// 解析u8字节流为QuinPacket的函数
    /// 
    /// Warning: 暂时硬编码默认第一层是link-Ethernet。
    pub fn parse_from_stream<'b>(input: &'b [u8], options: &QuinPacketOptions) -> QuinPacket<'b> {
        parse_ethernet_layer(input, options)
    }

    pub fn is_error(&self) -> bool {
        match self {
            QuinPacket::L1(l1) => l1.is_error(),
            QuinPacket::L2(l2) => l2.is_error(),
            QuinPacket::L3(l3) => l3.is_error(),
            QuinPacket::L4(l4) => l4.is_error(),
            QuinPacket::L5(l5) => l5.is_error(),
        }
    }
}

/// QuinPacketOptions为QuinPacket解析选项，提供多种解析特性。
/// 支持default：
/// ```
/// use parsing_parser::{QuinPacket, QuinPacketOptions};
///
/// let input = &[1,2,3,4,5,6];
/// QuinPacket::parse_from_stream(input, &QuinPacketOptions::default());
/// ```
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct QuinPacketOptions {
    pub stop: Option<ProtocolType>,
}

impl Default for QuinPacketOptions {
    fn default() -> Self {
        Self { stop: None }
    }
}
