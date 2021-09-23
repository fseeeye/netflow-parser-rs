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
use nom::number::complete::{be_u16, be_u24, be_u32, u8};
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
use std::ops::BitAnd;
#[allow(unused)]
use std::ops::BitOr;
#[allow(unused)]
use std::ops::BitXor;


use super::parse_l5_eof_layer;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct S7commHeader {
    pub s7_header: S7Header,
}

pub fn parse_s7comm_header(input: &[u8]) -> IResult<&[u8], S7commHeader> {
    let (input, s7_header) = parse_s7_header(input)?;
    Ok((
        input,
        S7commHeader {
            s7_header
        }
    ))
}

pub(crate) fn parse_s7comm_layer<'a>(input: &'a [u8], link_layer: LinkLayer, network_layer: NetworkLayer<'a>, transport_layer: TransportLayer<'a>, options: &QuinPacketOptions) -> QuinPacket<'a> {
    let current_layertype = LayerType::Application(ApplicationLayerType::S7comm);

    let (input, s7comm_header) = match parse_s7comm_header(input) {
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
        let application_layer = ApplicationLayer::S7comm(s7comm_header);
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

    let application_layer = ApplicationLayer::S7comm(s7comm_header);
    return parse_l5_eof_layer(input, link_layer, network_layer, transport_layer, application_layer, options);
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct S7Header {
    pub protocol_id: u8,
    pub rosctr: u8,
    pub redundancy_identification: [u8; 2],
    pub pdu_ref: u16,
    pub parameter_length: u16,
    pub data_length: u16,
}

pub fn parse_s7_header(input: &[u8]) -> IResult<&[u8], S7Header> {
    let (input, protocol_id) = u8(input)?;
    let (input, rosctr) = u8(input)?;
    let (input, redundancy_identification) = slice_u8_2(input)?;
    let (input, pdu_ref) = be_u16(input)?;
    let (input, parameter_length) = be_u16(input)?;
    let (input, data_length) = be_u16(input)?;
    Ok((
        input,
        S7Header {
            protocol_id,
            rosctr,
            redundancy_identification,
            pdu_ref,
            parameter_length,
            data_length
        }
    ))
}