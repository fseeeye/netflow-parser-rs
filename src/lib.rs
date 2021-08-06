//! Parsing-rs是流量解析引擎，致力于高效解析和安全稳定。
//!
//! ## Example
//! ```
//! use parsing_rs::*;
//!
//! match parse_quin_enum_packet(input, QuinPacketOptions::default()) {
//!     QuinPacket::L1(l1) => {
//!         println!("l1 packet: {:?}", l1);
//!     }
//!     QuinPacket::L2(l2) => {
//!         println!("l2 packet: {:?}", l2);
//!     }
//!     QuinPacket::L3(l3) => {
//!         println!("l3 packet: {:?}", l3);
//!     }
//!     QuinPacket::L4(l4) => {
//!         println!("l4 packet: {:?}", l4);
//!     }
//!     QuinPacket::L5(l5) => {
//!         println!("l5 packet: {:?}", l5);
//!     }
//! };
//! ```
//! 这仅仅是一个分级五元组Packet结构，我们将会支持更多种类数据结构的Packet以支持多元化使用场景。
mod errors;
mod layer;
mod layer_type;
mod packet_level;
mod packet_quin;
mod packet_vec;
mod parsers_map;
mod parsers;
mod traits;

pub use errors::ParseError;
pub use layer::{NetworkLayer, TransportLayer, Layer};
pub use layer_type::LayerType;
pub use packet_level::{L1Packet, L2Packet, L3Packet, L4Packet, L5Packet};
pub use packet_quin::{parse_quin_packet, QuinPacket, QuinPacketOptions};
pub use packet_vec::{VecPacket, VecPacketOptions};
pub use parsers_map::parsers_map_init;
pub use traits::*;

use std::collections::HashMap;
type Parser = Box<dyn Fn(&[u8]) -> nom::IResult<&[u8], (Layer, Option<LayerType>)>>;
type ParsersMap = HashMap<LayerType, Parser>;