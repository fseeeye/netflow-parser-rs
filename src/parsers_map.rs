use std::collections::HashMap;

use crate::errors::ParseError;
use crate::layer_type::LayerType;
use crate::ParsersMap;

pub fn parsers_map_init() -> ParsersMap {
    let mut parsers_map: ParsersMap = HashMap::new();
    parsers_map.insert(LayerType::Eof, Box::new(crate::parsers::parse_eof_fatlayer));
    parsers_map.insert(LayerType::Ethernet, Box::new(crate::parsers::parse_ethernet_fatlayer));
    parsers_map.insert(LayerType::Ipv4, Box::new(crate::parsers::parse_ipv4_fatlayer));
    parsers_map.insert(LayerType::Ipv6, Box::new(crate::parsers::parse_ipv6_fatlayer));
    parsers_map.insert(LayerType::ModbusReq, Box::new(crate::parsers::parse_modbus_req_fatlayer));
    parsers_map.insert(LayerType::ModbusRsp, Box::new(crate::parsers::parse_modbus_rsp_fatlayer));
    parsers_map.insert(LayerType::Tcp, Box::new(crate::parsers::parse_tcp_fatlayer));
    parsers_map.insert(LayerType::Udp, Box::new(crate::parsers::parse_udp_fatlayer));
    
    parsers_map.insert(LayerType::Error(ParseError::ParsingHeader), Box::new(crate::parsers::parse_error_layer));
    parsers_map.insert(LayerType::Error(ParseError::ParsingPayload), Box::new(crate::parsers::parse_error_layer));
    parsers_map.insert(LayerType::Error(ParseError::UnknownPayload), Box::new(crate::parsers::parse_error_layer));
    parsers_map.insert(LayerType::Error(ParseError::NotEndPayload), Box::new(crate::parsers::parse_error_layer));
    parsers_map.insert(LayerType::Error(ParseError::UnregisteredParser), Box::new(crate::parsers::parse_error_layer));
    parsers_map
}