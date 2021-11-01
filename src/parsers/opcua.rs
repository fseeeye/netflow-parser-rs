#[allow(unused)]
use nom::bits::bits;
#[allow(unused)]
use nom::bits::complete::take as take_bits;
#[allow(unused)]
use nom::bytes::complete::{tag, take};
#[allow(unused)]
use nom::combinator::{eof, map, peek};
#[allow(unused)]
use nom::error::{ErrorKind, Error};
#[allow(unused)]
use nom::multi::count;
#[allow(unused)]
use nom::number::complete::{be_u16, le_u16, be_u24, le_u24, be_u32, le_u32, u8};
#[allow(unused)]
use nom::sequence::tuple;
#[allow(unused)]
use nom::IResult;

#[allow(unused)]
use crate::errors::ParseError;
#[allow(unused)]
use crate::layer::{ApplicationLayer, LinkLayer, NetworkLayer, TransportLayer};
#[allow(unused)]
use crate::packet_level::{L1Packet, L2Packet, L3Packet, L4Packet, L5Packet};
#[allow(unused)]
use crate::packet_quin::{QuinPacket, QuinPacketOptions};
#[allow(unused)]
use crate::LayerType;
#[allow(unused)]
use crate::field_type::*;
#[allow(unused)]
use crate::layer_type::*;
#[allow(unused)]
use crate::utils::*;

#[allow(unused)]
use std::ops::BitAnd;
#[allow(unused)]
use std::ops::BitOr;
#[allow(unused)]
use std::ops::BitXor;
#[allow(unused)]
use std::convert::TryInto;


use super::parse_l5_eof_layer;

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OpcuaHeader {
    pub message_type_enum: MessageTypeEnum,
}

pub fn parse_opcua_header(input: &[u8]) -> IResult<&[u8], OpcuaHeader> {
    let (input, _message_type) = be_u24(input)?;
    let (input, message_type_enum) = parse_message_type_enum(input, _message_type)?;
    Ok((
        input,
        OpcuaHeader {
            message_type_enum
        }
    ))
}

pub(crate) fn parse_opcua_layer<'a>(input: &'a [u8], link_layer: LinkLayer, network_layer: NetworkLayer<'a>, transport_layer: TransportLayer<'a>, options: &QuinPacketOptions) -> QuinPacket<'a> {
    let current_layertype = LayerType::Application(ApplicationLayerType::Opcua);

    let (input, opcua_header) = match parse_opcua_header(input) {
        Ok(o) => o,
        Err(_e) => {
            return QuinPacket::L4(
                L4Packet {
                    link_layer,
                    network_layer,
                    transport_layer,
                    error: Some(ParseError::ParsingHeader),
                    remain: input,
                }
            )
        }
    };

    if Some(current_layertype) == options.stop {
        let application_layer = ApplicationLayer::Opcua(opcua_header);
        return QuinPacket::L5(
            L5Packet {
                link_layer,
                network_layer,
                transport_layer,
                application_layer,
                error: None,
                remain: input,
            }
        )
    };

    let application_layer = ApplicationLayer::Opcua(opcua_header);
    return parse_l5_eof_layer(input, link_layer, network_layer, transport_layer, application_layer, options);
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MessageTypeEnum {
    Hello {},
    Acknowledge {},
    Error {},
    ReverseHello {},
    Message {},
    CloseSecureChannel {}
}



pub fn parse_message_type_enum(input: &[u8], _message_type: u32) -> IResult<&[u8], MessageTypeEnum> {
    let (input, message_type_enum) = match _message_type {
        0x48454c => {
            Ok((
                input,
                MessageTypeEnum::Hello {}
            ))
        }
        0x41434b => {
            Ok((
                input,
                MessageTypeEnum::Acknowledge {}
            ))
        }
        0x455252 => {
            Ok((
                input,
                MessageTypeEnum::Error {}
            ))
        }
        0x524845 => {
            Ok((
                input,
                MessageTypeEnum::ReverseHello {}
            ))
        }
        0x4d5347 => {
            Ok((
                input,
                MessageTypeEnum::Message {}
            ))
        }
        0x4f504e => {
            Ok((
                input,
                MessageTypeEnum::Message {}
            ))
        }
        0x434c4f => {
            Ok((
                input,
                MessageTypeEnum::CloseSecureChannel {}
            ))
        }
        _ =>  Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }?;
    Ok((input, message_type_enum))
}