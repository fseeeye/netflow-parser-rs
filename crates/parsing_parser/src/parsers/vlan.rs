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
use nom::number::complete::{be_u16, le_u16, be_u24, be_u64, le_u24, be_u32, le_u32, u8, le_u64};
#[allow(unused)]
use nom::sequence::tuple;
#[allow(unused)]
use nom::IResult;
#[allow(unused)]
use tracing::{error, warn, info, debug};

#[allow(unused)]
use crate::errors::ParseError;
#[allow(unused)]
use crate::layer::{ApplicationLayer, LinkLayer, NetworkLayer, TransportLayer};
#[allow(unused)]
use crate::packet::{QuinPacket, QuinPacketOptions, L1Packet, L2Packet, L3Packet, L4Packet, L5Packet};
#[allow(unused)]
use crate::ProtocolType;
#[allow(unused)]
use crate::field_type::*;
#[allow(unused)]
use crate::protocol::*;
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


use super::{parse_sv_layer, parse_l3_eof_layer};

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VlanHeader {
    pub priority: u8,
    pub dei: u8,
    pub id: u16,
    pub vtype: u16,
}

pub fn parse_vlan_header(input: &[u8]) -> IResult<&[u8], VlanHeader> {
    debug!(target: "PARSER(parse_vlan_header)", "struct VlanHeader");
    let (input, (priority, dei, id)): (&[u8], (u8, u8, u16))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
        tuple((take_bits(3usize), take_bits(1usize), take_bits(12usize)))
    )(input)?;
    let (input, vtype) = be_u16(input)?;
    Ok((
        input,
        VlanHeader {
            priority, dei, id,
            vtype
        }
    ))
}

pub fn parse_vlan_layer<'a>(input: &'a [u8], link_layer: LinkLayer, options: &QuinPacketOptions) -> QuinPacket<'a> {
    info!(target: "PARSER(vlan::parse_vlan_layer)", "parsing Vlan protocol.");
    let current_prototype = ProtocolType::Network(NetworkProtocol::Vlan);

    let (input, vlan_header) = match parse_vlan_header(input) {
        Ok(o) => o,
        Err(e) => {
            error!(
                target: "PARSER(vlan::parse_vlan_layer)",
                error = ?e
            );

            let offset = match e {
                nom::Err::Error(error) => input.len() - error.input.len(),
                _ => usize::MAX
            };

            return QuinPacket::L2(
                L2Packet {
                    link_layer,
                    error: Some(ParseError::ParsingHeader{
                    protocol: current_prototype,
                    offset
                }),
                    remain: input,
                }
            )
        }
    };

    if Some(current_prototype) == options.stop {
        let network_layer = NetworkLayer::Vlan(vlan_header);
        return QuinPacket::L3(
            L3Packet {
                link_layer,
                network_layer,
                error: None,
                remain: input,
            }
        )
    };

    if input.len() == 0 {
        let network_layer = NetworkLayer::Vlan(vlan_header);
        return parse_l3_eof_layer(input, link_layer, network_layer, options);
    }
    match vlan_header.vtype {
        0x88ba => {
            let network_layer = NetworkLayer::Vlan(vlan_header);
            parse_sv_layer(input, link_layer, network_layer, options)
        },
        _ => {
            let network_layer = NetworkLayer::Vlan(vlan_header);
            return QuinPacket::L3(
                L3Packet {
                    link_layer,
                    network_layer,
                    error: None,
                    remain: input,
                }
            )
        }
    }
}
