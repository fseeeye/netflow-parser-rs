mod parsers;
mod packet;
mod layer;
mod layer_type;
mod parsers_map;
mod errors;
mod traits;

pub use traits::*;
pub use packet::{VecPacket, VecPacketOptions};
pub use parsers_map::parsers_map_init;
pub use layer_type::LayerType;
pub use layer::Layer;

use std::collections::HashMap;

type Parser = Box<dyn Fn(&[u8]) -> nom::IResult<&[u8], (Layer, Option<LayerType>)>>;
type ParsersMap = HashMap<LayerType, Parser>;