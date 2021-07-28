mod parsers;
mod packet_vec;
mod packet_quin;
mod layer;
mod layer_type;
mod parsers_map;
mod errors;
mod traits;


pub use traits::*;
pub use layer_type::LayerType;
pub use layer::Layer;
pub use parsers_map::parsers_map_init;
pub use packet_vec::{VecPacket, VecPacketOptions};
pub use packet_quin::QuinPacket;


use std::collections::HashMap;

type Parser = Box<dyn Fn(&[u8]) -> nom::IResult<&[u8], (Layer, Option<LayerType>)>>;
type ParsersMap = HashMap<LayerType, Parser>;