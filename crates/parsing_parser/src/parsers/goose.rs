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


use super::parse_l3_eof_layer;

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct GooseHeader<'a> {
    pub appid: u16,
    pub length: u16,
    pub reserve_1: u16,
    pub reserve_2: u16,
    pub goose_pdu: GoosePDU<'a>,
}

pub fn parse_goose_header(input: &[u8]) -> IResult<&[u8], GooseHeader> {
    debug!(target: "PARSER(parse_goose_header)", "struct GooseHeader");
    let (input, appid) = be_u16(input)?;
    let (input, length) = be_u16(input)?;
    let (input, reserve_1) = be_u16(input)?;
    let (input, reserve_2) = be_u16(input)?;
    let (input, _goose_pdu_tl) = ber_tl(input)?;
    let (input, goose_pdu) = parse_goose_pdu(input)?;
    Ok((
        input,
        GooseHeader {
            appid,
            length,
            reserve_1,
            reserve_2,
            goose_pdu
        }
    ))
}

pub fn parse_goose_layer<'a>(input: &'a [u8], link_layer: LinkLayer, options: &QuinPacketOptions) -> QuinPacket<'a> {
    info!(target: "PARSER(goose::parse_goose_layer)", "parsing Goose protocol.");
    let current_prototype = ProtocolType::Network(NetworkProtocol::Goose);

    let (input, goose_header) = match parse_goose_header(input) {
        Ok(o) => o,
        Err(e) => {
            error!(
                target: "PARSER(goose::parse_goose_layer)",
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
        let network_layer = NetworkLayer::Goose(goose_header);
        return QuinPacket::L3(
            L3Packet {
                link_layer,
                network_layer,
                error: None,
                remain: input,
            }
        )
    };

    let network_layer = NetworkLayer::Goose(goose_header);
    return parse_l3_eof_layer(input, link_layer, network_layer, options);
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct GoosePDU<'a> {
    pub gocb_ref: &'a [u8],
    pub time_allowed_to_live: &'a [u8],
    pub dat_set: &'a [u8],
    pub go_id: &'a [u8],
    pub t: &'a [u8],
    pub st_num: &'a [u8],
    pub sq_num: &'a [u8],
    pub simulation: &'a [u8],
    pub conf_rev: &'a [u8],
    pub nds_com: &'a [u8],
    pub num_dat_set_entries: &'a [u8],
    pub all_data: Vec<&'a [u8]>,
}

pub fn parse_goose_pdu(input: &[u8]) -> IResult<&[u8], GoosePDU> {
    debug!(target: "PARSER(parse_goose_pdu)", "struct GoosePDU");
    let (input, gocb_ref) = ber_tl_v(input)?;
    let (input, time_allowed_to_live) = ber_tl_v(input)?;
    let (input, dat_set) = ber_tl_v(input)?;
    let (input, go_id) = ber_tl_v(input)?;
    let (input, t) = ber_tl_v(input)?;
    let (input, st_num) = ber_tl_v(input)?;
    let (input, sq_num) = ber_tl_v(input)?;
    let (input, simulation) = ber_tl_v(input)?;
    let (input, conf_rev) = ber_tl_v(input)?;
    let (input, nds_com) = ber_tl_v(input)?;
    let (input, num_dat_set_entries) = ber_tl_v(input)?;
    let (input, _all_data_tl) = ber_tl(input)?;
    /* LimitedLenVecLoopField Start */
    let mut all_data = Vec::new();
    let mut _all_data: &[u8];
    let mut input = input;
    let len_flag = input.len() - _all_data_tl.length as usize;
    while input.len() > len_flag {
        (input, _all_data) = ber_tl_v(input)?;
        all_data.push(_all_data);
    }
    let input = input;
    /* LimitedLenVecLoopField End. */
    Ok((
        input,
        GoosePDU {
            gocb_ref,
            time_allowed_to_live,
            dat_set,
            go_id,
            t,
            st_num,
            sq_num,
            simulation,
            conf_rev,
            nds_com,
            num_dat_set_entries,
            all_data
        }
    ))
}