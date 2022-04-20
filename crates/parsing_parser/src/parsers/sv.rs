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


use super::parse_l4_eof_layer;

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SvHeader<'a> {
    pub appid: u16,
    pub length: u16,
    pub reserve_1: u16,
    pub reserve_2: u16,
    pub sav_pdu_tl: BerTL,
    pub sav_pdu: SavPDU<'a>,
}

pub fn parse_sv_header(input: &[u8]) -> IResult<&[u8], SvHeader> {
    debug!(target: "PARSER(parse_sv_header)", "struct SvHeader");
    let (input, appid) = be_u16(input)?;
    let (input, length) = be_u16(input)?;
    let (input, reserve_1) = be_u16(input)?;
    let (input, reserve_2) = be_u16(input)?;
    let (input, sav_pdu_tl) = ber_tl(input)?;
    let (input, sav_pdu) = parse_sav_pdu(input)?;
    Ok((
        input,
        SvHeader {
            appid,
            length,
            reserve_1,
            reserve_2,
            sav_pdu_tl,
            sav_pdu
        }
    ))
}

pub fn parse_sv_layer<'a>(input: &'a [u8], link_layer: LinkLayer, network_layer: NetworkLayer<'a>, options: &QuinPacketOptions) -> QuinPacket<'a> {
    info!(target: "PARSER(sv::parse_sv_layer)", "parsing Sv protocol.");
    let current_prototype = ProtocolType::Transport(TransportProtocol::Sv);
    let input_size = input.len();

    let (input, sv_header) = match parse_sv_header(input) {
        Ok(o) => o,
        Err(e) => {
            error!(
                target: "PARSER(sv::parse_sv_layer)",
                error = ?e
            );
            return QuinPacket::L3(
                L3Packet {
                    link_layer,
                    network_layer,
                    error: Some(ParseError::ParsingHeader{
                    protocol: current_prototype,
                    offset: input_size - input.len()
                }),
                    remain: input,
                }
            )
        }
    };

    if Some(current_prototype) == options.stop {
        let transport_layer = TransportLayer::Sv(sv_header);
        return QuinPacket::L4(
            L4Packet {
                link_layer,
                network_layer,
                transport_layer,
                error: None,
                remain: input,
            }
        )
    };

    let transport_layer = TransportLayer::Sv(sv_header);
    return parse_l4_eof_layer(input, link_layer, network_layer, transport_layer, options);
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Asdu<'a> {
    pub asdu_tl: BerTL,
    pub sv_id: &'a [u8],
    pub cmp_cnt: &'a [u8],
    pub conf_rev: &'a [u8],
    pub smp_synch: &'a [u8],
    pub seq_data: &'a [u8],
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SavPDU<'a> {
    pub no_asdu: &'a [u8],
    pub seq_asdu_tl: BerTL,
    pub seq_asdu: Vec<Asdu<'a>>,
}

pub fn parse_asdu(input: &[u8]) -> IResult<&[u8], Asdu> {
    debug!(target: "PARSER(parse_asdu)", "struct Asdu");
    let (input, asdu_tl) = ber_tl(input)?;
    let (input, sv_id) = ber_tl_v(input)?;
    let (input, cmp_cnt) = ber_tl_v(input)?;
    let (input, conf_rev) = ber_tl_v(input)?;
    let (input, smp_synch) = ber_tl_v(input)?;
    let (input, seq_data) = ber_tl_v(input)?;
    Ok((
        input,
        Asdu {
            asdu_tl,
            sv_id,
            cmp_cnt,
            conf_rev,
            smp_synch,
            seq_data
        }
    ))
}

pub fn parse_sav_pdu(input: &[u8]) -> IResult<&[u8], SavPDU> {
    debug!(target: "PARSER(parse_sav_pdu)", "struct SavPDU");
    let (input, no_asdu) = ber_tl_v(input)?;
    let (input, seq_asdu_tl) = ber_tl(input)?;
    /* LimitedLenVecLoopField Start */
    let mut seq_asdu = Vec::new();
    let mut _seq_asdu: Asdu;
    let mut input = input;
    let len_flag = input.len() - seq_asdu_tl.length as usize;
    while input.len() > len_flag {
        (input, _seq_asdu) = parse_asdu(input)?;
        seq_asdu.push(_seq_asdu);
    }
    let input = input;
    /* LimitedLenVecLoopField End. */
    Ok((
        input,
        SavPDU {
            no_asdu,
            seq_asdu_tl,
            seq_asdu
        }
    ))
}