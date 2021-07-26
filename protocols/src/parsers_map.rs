use std::collections::HashMap;

use crate::errors::ParseError;
use crate::layer_type::LayerType;
use crate::ParsersMap;

pub fn parsers_map_init() -> ParsersMap {
    let mut parsers_map: ParsersMap = HashMap::new();
    parsers_map.insert(LayerType::Ethernet, Box::new(crate::parsers::parse_ethernet_layer));
    parsers_map.insert(LayerType::Error(ParseError::ParsingHeader), Box::new(crate::parsers::parse_error_layer));
    parsers_map.insert(LayerType::Error(ParseError::ParsingPayload), Box::new(crate::parsers::parse_error_layer));
    parsers_map.insert(LayerType::Error(ParseError::UnknownPayload), Box::new(crate::parsers::parse_error_layer));
    parsers_map.insert(LayerType::Error(ParseError::UnregisteredParser), Box::new(crate::parsers::parse_error_layer));
    parsers_map
}