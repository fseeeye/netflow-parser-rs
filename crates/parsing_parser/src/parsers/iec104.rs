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


use super::parse_l5_eof_layer;

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Iec104Header {
    pub iec104_blocks: Vec<Iec104Block>,
}

pub fn parse_iec104_header(input: &[u8]) -> IResult<&[u8], Iec104Header> {
    /* UnlimitedVecLoopField Start */
    let mut iec104_blocks = Vec::new();
    let mut _iec104_blocks: Iec104Block;
    let mut input = input;
    while input.len() > 0 {
        (input, _iec104_blocks) = parse_iec104_block(input)?;
        iec104_blocks.push(_iec104_blocks);
    }
    let input = input;
    /* UnlimitedVecLoopField End. */
    Ok((
        input,
        Iec104Header {
            iec104_blocks
        }
    ))
}

pub fn parse_iec104_layer<'a>(input: &'a [u8], link_layer: LinkLayer, network_layer: NetworkLayer<'a>, transport_layer: TransportLayer<'a>, options: &QuinPacketOptions) -> QuinPacket<'a> {
    let current_layertype = ProtocolType::Application(ApplicationProtocol::Iec104);

    let (input, iec104_header) = match parse_iec104_header(input) {
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
        let application_layer = ApplicationLayer::Iec104(iec104_header);
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

    let application_layer = ApplicationLayer::Iec104(iec104_header);
    return parse_l5_eof_layer(input, link_layer, network_layer, transport_layer, application_layer, options);
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum IoaTypeEnum {
    M_SP_NA_1 {
         siq_iv: u8,
         siq_nt: u8,
         siq_sb: u8,
         siq_bl: u8,
         siq_spi: u8,
    },
    M_SP_TA_1 {
         siq_iv: u8,
         siq_nt: u8,
         siq_sb: u8,
         siq_bl: u8,
         siq_spi: u8,
         cp24time_ms: u16,
         cp24time_iv: u8,
         cp24time_min: u8,
    },
    M_DP_NA_1 {
         diq_iv: u8,
         diq_nt: u8,
         diq_sb: u8,
         diq_bl: u8,
         diq_dpi: u8,
    },
    M_DP_TA_1 {
         diq_iv: u8,
         diq_nt: u8,
         diq_sb: u8,
         diq_bl: u8,
         diq_dpi: u8,
         cp24time_ms: u16,
         cp24time_iv: u8,
         cp24time_min: u8,
    },
    M_ST_NA_1 {
         vti_t: u8,
         vti_value: u8,
         qds_iv: u8,
         qds_nt: u8,
         qds_sb: u8,
         qds_bl: u8,
         qds_ov: u8,
    },
    M_ST_TA_1 {
         vti_t: u8,
         vti_value: u8,
         qds_iv: u8,
         qds_nt: u8,
         qds_sb: u8,
         qds_bl: u8,
         qds_ov: u8,
         cp24time_ms: u16,
         cp24time_iv: u8,
         cp24time_min: u8,
    },
    M_BO_NA_1 {
         bsi: [u8; 4],
         qds_iv: u8,
         qds_nt: u8,
         qds_sb: u8,
         qds_bl: u8,
         qds_ov: u8,
    },
    M_BO_TA_1 {
         bsi: [u8; 4],
         qds_iv: u8,
         qds_nt: u8,
         qds_sb: u8,
         qds_bl: u8,
         qds_ov: u8,
         cp24time_ms: u16,
         cp24time_iv: u8,
         cp24time_min: u8,
    },
    M_ME_NA_1 {
         nva_u16: u16,
         qds_iv: u8,
         qds_nt: u8,
         qds_sb: u8,
         qds_bl: u8,
         qds_ov: u8,
    },
    M_ME_TA_1 {
         nva_u16: u16,
         qds_iv: u8,
         qds_nt: u8,
         qds_sb: u8,
         qds_bl: u8,
         qds_ov: u8,
         cp24time_ms: u16,
         cp24time_iv: u8,
         cp24time_min: u8,
    },
    M_ME_NB_1 {
         sva: u16,
         qds_iv: u8,
         qds_nt: u8,
         qds_sb: u8,
         qds_bl: u8,
         qds_ov: u8,
    },
    M_ME_TB_1 {
         sva: u16,
         qds_iv: u8,
         qds_nt: u8,
         qds_sb: u8,
         qds_bl: u8,
         qds_ov: u8,
         cp24time_ms: u16,
         cp24time_iv: u8,
         cp24time_min: u8,
    },
    M_ME_NC_1 {
         flt: u32,
         qds_iv: u8,
         qds_nt: u8,
         qds_sb: u8,
         qds_bl: u8,
         qds_ov: u8,
    },
    M_ME_TC_1 {
         flt: u32,
         qds_iv: u8,
         qds_nt: u8,
         qds_sb: u8,
         qds_bl: u8,
         qds_ov: u8,
         cp24time_ms: u16,
         cp24time_iv: u8,
         cp24time_min: u8,
    },
    M_IT_NA_1 {
         bcr_count: u32,
         bcr_iv: u8,
         bcr_ca: u8,
         bcr_cy: u8,
         bcr_sq: u8,
    },
    M_IT_TA_1 {
         bcr_count: u32,
         bcr_iv: u8,
         bcr_ca: u8,
         bcr_cy: u8,
         bcr_sq: u8,
         cp24time_ms: u16,
         cp24time_iv: u8,
         cp24time_min: u8,
    },
    M_PS_NA_1 {},
    M_ME_ND_1 {
         nva_u16: u16,
    },
    M_SP_TB_1 {
         siq_iv: u8,
         siq_nt: u8,
         siq_sb: u8,
         siq_bl: u8,
         siq_spi: u8,
         cp56time_ms: u16,
         cp56time_iv: u8,
         cp56time_min: u8,
         cp56time_su: u8,
         cp56time_hour: u8,
         cp56time_dow: u8,
         cp56time_day: u8,
         cp56time_month: u8,
         cp56time_year: u8,
    },
    M_DP_TB_1 {
         diq_iv: u8,
         diq_nt: u8,
         diq_sb: u8,
         diq_bl: u8,
         diq_dpi: u8,
         cp56time_ms: u16,
         cp56time_iv: u8,
         cp56time_min: u8,
         cp56time_su: u8,
         cp56time_hour: u8,
         cp56time_dow: u8,
         cp56time_day: u8,
         cp56time_month: u8,
         cp56time_year: u8,
    },
    M_ST_TB_1 {
         vti_t: u8,
         vti_value: u8,
         qds_iv: u8,
         qds_nt: u8,
         qds_sb: u8,
         qds_bl: u8,
         qds_ov: u8,
         cp56time_ms: u16,
         cp56time_iv: u8,
         cp56time_min: u8,
         cp56time_su: u8,
         cp56time_hour: u8,
         cp56time_dow: u8,
         cp56time_day: u8,
         cp56time_month: u8,
         cp56time_year: u8,
    },
    M_BO_TB_1 {
         bsi: [u8; 4],
         qds_iv: u8,
         qds_nt: u8,
         qds_sb: u8,
         qds_bl: u8,
         qds_ov: u8,
         cp56time_ms: u16,
         cp56time_iv: u8,
         cp56time_min: u8,
         cp56time_su: u8,
         cp56time_hour: u8,
         cp56time_dow: u8,
         cp56time_day: u8,
         cp56time_month: u8,
         cp56time_year: u8,
    },
    M_ME_TD_1 {
         nva_u16: u16,
         qds_iv: u8,
         qds_nt: u8,
         qds_sb: u8,
         qds_bl: u8,
         qds_ov: u8,
         cp56time_ms: u16,
         cp56time_iv: u8,
         cp56time_min: u8,
         cp56time_su: u8,
         cp56time_hour: u8,
         cp56time_dow: u8,
         cp56time_day: u8,
         cp56time_month: u8,
         cp56time_year: u8,
    },
    M_ME_TE_1 {
         sva: u16,
         qds_iv: u8,
         qds_nt: u8,
         qds_sb: u8,
         qds_bl: u8,
         qds_ov: u8,
         cp56time_ms: u16,
         cp56time_iv: u8,
         cp56time_min: u8,
         cp56time_su: u8,
         cp56time_hour: u8,
         cp56time_dow: u8,
         cp56time_day: u8,
         cp56time_month: u8,
         cp56time_year: u8,
    },
    M_ME_TF_1 {
         flt: u32,
         qds_iv: u8,
         qds_nt: u8,
         qds_sb: u8,
         qds_bl: u8,
         qds_ov: u8,
         cp56time_ms: u16,
         cp56time_iv: u8,
         cp56time_min: u8,
         cp56time_su: u8,
         cp56time_hour: u8,
         cp56time_dow: u8,
         cp56time_day: u8,
         cp56time_month: u8,
         cp56time_year: u8,
    },
    M_IT_TB_1 {
         bcr_count: u32,
         bcr_iv: u8,
         bcr_ca: u8,
         bcr_cy: u8,
         bcr_sq: u8,
         cp56time_ms: u16,
         cp56time_iv: u8,
         cp56time_min: u8,
         cp56time_su: u8,
         cp56time_hour: u8,
         cp56time_dow: u8,
         cp56time_day: u8,
         cp56time_month: u8,
         cp56time_year: u8,
    },
    M_EP_TD_1 {},
    M_EP_TE_1 {},
    M_EP_TF_1 {},
    S_IT_TC_1 {},
    C_SC_NA_1 {
         sco_se: u8,
         sco_qu: u8,
         sco_on: u8,
    },
    C_DC_NA_1 {
         dco_se: u8,
         dco_qu: u8,
         dco_on: u8,
    },
    C_RC_NA_1 {
         rco_se: u8,
         rco_qu: u8,
         rco_up: u8,
    },
    C_SE_NA_1 {
         nva_u16: u16,
         qos_ql: u8,
         qos_se: u8,
    },
    C_SE_NB_1 {
         sva: u16,
         qos_ql: u8,
         qos_se: u8,
    },
    C_SE_NC_1 {
         flt: u32,
         qos_ql: u8,
         qos_se: u8,
    },
    C_BO_NA_1 {
         bsi: [u8; 4],
    },
    C_SC_TA_1 {
         sco_se: u8,
         sco_qu: u8,
         sco_on: u8,
         cp56time_ms: u16,
         cp56time_iv: u8,
         cp56time_min: u8,
         cp56time_su: u8,
         cp56time_hour: u8,
         cp56time_dow: u8,
         cp56time_day: u8,
         cp56time_month: u8,
         cp56time_year: u8,
    },
    C_DC_TA_1 {
         dco_se: u8,
         dco_qu: u8,
         dco_on: u8,
         cp56time_ms: u16,
         cp56time_iv: u8,
         cp56time_min: u8,
         cp56time_su: u8,
         cp56time_hour: u8,
         cp56time_dow: u8,
         cp56time_day: u8,
         cp56time_month: u8,
         cp56time_year: u8,
    },
    C_RC_TA_1 {
         rco_se: u8,
         rco_qu: u8,
         rco_up: u8,
         cp56time_ms: u16,
         cp56time_iv: u8,
         cp56time_min: u8,
         cp56time_su: u8,
         cp56time_hour: u8,
         cp56time_dow: u8,
         cp56time_day: u8,
         cp56time_month: u8,
         cp56time_year: u8,
    },
    C_SE_TA_1 {
         nva_u16: u16,
         qos_ql: u8,
         qos_se: u8,
         cp56time_ms: u16,
         cp56time_iv: u8,
         cp56time_min: u8,
         cp56time_su: u8,
         cp56time_hour: u8,
         cp56time_dow: u8,
         cp56time_day: u8,
         cp56time_month: u8,
         cp56time_year: u8,
    },
    C_SE_TB_1 {
         sva: u16,
         qos_ql: u8,
         qos_se: u8,
         cp56time_ms: u16,
         cp56time_iv: u8,
         cp56time_min: u8,
         cp56time_su: u8,
         cp56time_hour: u8,
         cp56time_dow: u8,
         cp56time_day: u8,
         cp56time_month: u8,
         cp56time_year: u8,
    },
    C_SE_TC_1 {
         flt: u32,
         qos_ql: u8,
         qos_se: u8,
         cp56time_ms: u16,
         cp56time_iv: u8,
         cp56time_min: u8,
         cp56time_su: u8,
         cp56time_hour: u8,
         cp56time_dow: u8,
         cp56time_day: u8,
         cp56time_month: u8,
         cp56time_year: u8,
    },
    C_BO_TA_1 {
         bsi: [u8; 4],
         qos_ql: u8,
         qos_se: u8,
         cp56time_ms: u16,
         cp56time_iv: u8,
         cp56time_min: u8,
         cp56time_su: u8,
         cp56time_hour: u8,
         cp56time_dow: u8,
         cp56time_day: u8,
         cp56time_month: u8,
         cp56time_year: u8,
    },
    M_EI_NA_1 {
         coi_r: u8,
         coi_i: u8,
    },
    S_CH_NA_1 {},
    S_RP_NA_1 {},
    S_AR_NA_1 {},
    S_KR_NA_1 {},
    S_KS_NA_1 {},
    S_KC_NA_1 {},
    S_ER_NA_1 {},
    S_US_NA_1 {},
    S_UQ_NA_1 {},
    S_UR_NA_1 {},
    S_UK_NA_1 {},
    S_UA_NA_1 {},
    S_UC_NA_1 {},
    C_IC_NA_1 {
         qoi: u8,
    },
    C_CI_NA_1 {
         qcc_frz: u8,
         qcc_rqt: u8,
    },
    C_RD_NA_1 {},
    C_CS_NA_1 {
         cp56time_ms: u16,
         cp56time_iv: u8,
         cp56time_min: u8,
         cp56time_su: u8,
         cp56time_hour: u8,
         cp56time_dow: u8,
         cp56time_day: u8,
         cp56time_month: u8,
         cp56time_year: u8,
    },
    C_RP_NA_1 {
         qrp: u8,
    },
    C_TS_TA_1 {},
    P_ME_NA_1 {
         nva_u16: u16,
         qpm_pop: u8,
         qpm_lpc: u8,
         qpm_kpa: u8,
    },
    P_ME_NB_1 {
         sva: u16,
         qpm_pop: u8,
         qpm_lpc: u8,
         qpm_kpa: u8,
    },
    P_ME_NC_1 {
         flt: u32,
         qpm_pop: u8,
         qpm_lpc: u8,
         qpm_kpa: u8,
    },
    P_AC_NA_1 {},
    F_FR_NA_1 {},
    F_SR_NA_1 {},
    F_SC_NA_1 {},
    F_LS_NA_1 {},
    F_AF_NA_1 {},
    F_SG_NA_1 {},
    F_DR_NA_1 {},
    F_SC_NB_1 {}
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Ioa {
    pub ioa: u32,
    pub ioa_type_enum: IoaTypeEnum,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IecAsdu {
    pub type_id: u8,
    pub sq: u8,
    pub num_ix: u8,
    pub test: u8,
    pub negative: u8,
    pub cause_tx: u8,
    pub oa: u8,
    pub addr: u16,
    pub ioa_array: Vec<Ioa>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TypeBlock {
    TypeI {
         type104: u8,
         apci_txid: u16,
         apci_rxid: u16,
         iec_asdu: IecAsdu,
    },
    TypeS {
         type104: u8,
         apci_rxid: u16,
    },
    TypeU {
         type104: u8,
         apci_utype: u8,
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Iec104Block {
    pub start: u8,
    pub apdu_len: u8,
    pub type_block: TypeBlock,
}



pub fn parse_ioa_type_enum(input: &[u8], type_id: u8) -> IResult<&[u8], IoaTypeEnum> {
    let (input, ioa_type_enum) = match type_id {
        0x01 => {
            let (input, (siq_iv, siq_nt, siq_sb, siq_bl, _, siq_spi)): (&[u8], (u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(3usize), take_bits(1usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::M_SP_NA_1 {
                    siq_iv, siq_nt, siq_sb, siq_bl, siq_spi
                }
            ))
        }
        0x02 => {
            let (input, (siq_iv, siq_nt, siq_sb, siq_bl, _, siq_spi)): (&[u8], (u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(3usize), take_bits(1usize)))
            )(input)?;
            let (input, cp24time_ms) = le_u16(input)?;
            let (input, (cp24time_iv, cp24time_min)): (&[u8], (u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::M_SP_TA_1 {
                    siq_iv, siq_nt, siq_sb, siq_bl, siq_spi,
                    cp24time_ms,
                    cp24time_iv, cp24time_min
                }
            ))
        }
        0x03 => {
            let (input, (diq_iv, diq_nt, diq_sb, diq_bl, _, diq_dpi)): (&[u8], (u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(2usize), take_bits(2usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::M_DP_NA_1 {
                    diq_iv, diq_nt, diq_sb, diq_bl, diq_dpi
                }
            ))
        }
        0x04 => {
            let (input, (diq_iv, diq_nt, diq_sb, diq_bl, _, diq_dpi)): (&[u8], (u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(2usize), take_bits(2usize)))
            )(input)?;
            let (input, cp24time_ms) = le_u16(input)?;
            let (input, (cp24time_iv, cp24time_min)): (&[u8], (u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::M_DP_TA_1 {
                    diq_iv, diq_nt, diq_sb, diq_bl, diq_dpi,
                    cp24time_ms,
                    cp24time_iv, cp24time_min
                }
            ))
        }
        0x05 => {
            let (input, (vti_t, vti_value)): (&[u8], (u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize)))
            )(input)?;
            let (input, (qds_iv, qds_nt, qds_sb, qds_bl, _, qds_ov)): (&[u8], (u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(3usize), take_bits(1usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::M_ST_NA_1 {
                    vti_t, vti_value,
                    qds_iv, qds_nt, qds_sb, qds_bl, qds_ov
                }
            ))
        }
        0x06 => {
            let (input, (vti_t, vti_value)): (&[u8], (u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize)))
            )(input)?;
            let (input, (qds_iv, qds_nt, qds_sb, qds_bl, _, qds_ov)): (&[u8], (u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(3usize), take_bits(1usize)))
            )(input)?;
            let (input, cp24time_ms) = le_u16(input)?;
            let (input, (cp24time_iv, cp24time_min)): (&[u8], (u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::M_ST_TA_1 {
                    vti_t, vti_value,
                    qds_iv, qds_nt, qds_sb, qds_bl, qds_ov,
                    cp24time_ms,
                    cp24time_iv, cp24time_min
                }
            ))
        }
        0x07 => {
            let (input, bsi) = slice_u8_4(input)?;
            let (input, (qds_iv, qds_nt, qds_sb, qds_bl, _, qds_ov)): (&[u8], (u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(3usize), take_bits(1usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::M_BO_NA_1 {
                    bsi,
                    qds_iv, qds_nt, qds_sb, qds_bl, qds_ov
                }
            ))
        }
        0x08 => {
            let (input, bsi) = slice_u8_4(input)?;
            let (input, (qds_iv, qds_nt, qds_sb, qds_bl, _, qds_ov)): (&[u8], (u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(3usize), take_bits(1usize)))
            )(input)?;
            let (input, cp24time_ms) = le_u16(input)?;
            let (input, (cp24time_iv, cp24time_min)): (&[u8], (u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::M_BO_TA_1 {
                    bsi,
                    qds_iv, qds_nt, qds_sb, qds_bl, qds_ov,
                    cp24time_ms,
                    cp24time_iv, cp24time_min
                }
            ))
        }
        0x09 => {
            let (input, nva_u16) = le_u16(input)?;
            let (input, (qds_iv, qds_nt, qds_sb, qds_bl, _, qds_ov)): (&[u8], (u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(3usize), take_bits(1usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::M_ME_NA_1 {
                    nva_u16,
                    qds_iv, qds_nt, qds_sb, qds_bl, qds_ov
                }
            ))
        }
        0x0a => {
            let (input, nva_u16) = le_u16(input)?;
            let (input, (qds_iv, qds_nt, qds_sb, qds_bl, _, qds_ov)): (&[u8], (u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(3usize), take_bits(1usize)))
            )(input)?;
            let (input, cp24time_ms) = le_u16(input)?;
            let (input, (cp24time_iv, cp24time_min)): (&[u8], (u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::M_ME_TA_1 {
                    nva_u16,
                    qds_iv, qds_nt, qds_sb, qds_bl, qds_ov,
                    cp24time_ms,
                    cp24time_iv, cp24time_min
                }
            ))
        }
        0x0b => {
            let (input, sva) = be_u16(input)?;
            let (input, (qds_iv, qds_nt, qds_sb, qds_bl, _, qds_ov)): (&[u8], (u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(3usize), take_bits(1usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::M_ME_NB_1 {
                    sva,
                    qds_iv, qds_nt, qds_sb, qds_bl, qds_ov
                }
            ))
        }
        0x0c => {
            let (input, sva) = be_u16(input)?;
            let (input, (qds_iv, qds_nt, qds_sb, qds_bl, _, qds_ov)): (&[u8], (u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(3usize), take_bits(1usize)))
            )(input)?;
            let (input, cp24time_ms) = le_u16(input)?;
            let (input, (cp24time_iv, cp24time_min)): (&[u8], (u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::M_ME_TB_1 {
                    sva,
                    qds_iv, qds_nt, qds_sb, qds_bl, qds_ov,
                    cp24time_ms,
                    cp24time_iv, cp24time_min
                }
            ))
        }
        0x0d => {
            let (input, flt) = be_u32(input)?;
            let (input, (qds_iv, qds_nt, qds_sb, qds_bl, _, qds_ov)): (&[u8], (u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(3usize), take_bits(1usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::M_ME_NC_1 {
                    flt,
                    qds_iv, qds_nt, qds_sb, qds_bl, qds_ov
                }
            ))
        }
        0x0e => {
            let (input, flt) = be_u32(input)?;
            let (input, (qds_iv, qds_nt, qds_sb, qds_bl, _, qds_ov)): (&[u8], (u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(3usize), take_bits(1usize)))
            )(input)?;
            let (input, cp24time_ms) = le_u16(input)?;
            let (input, (cp24time_iv, cp24time_min)): (&[u8], (u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::M_ME_TC_1 {
                    flt,
                    qds_iv, qds_nt, qds_sb, qds_bl, qds_ov,
                    cp24time_ms,
                    cp24time_iv, cp24time_min
                }
            ))
        }
        0x0f => {
            let (input, bcr_count) = be_u32(input)?;
            let (input, (bcr_iv, bcr_ca, bcr_cy, bcr_sq)): (&[u8], (u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(5usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::M_IT_NA_1 {
                    bcr_count,
                    bcr_iv, bcr_ca, bcr_cy, bcr_sq
                }
            ))
        }
        0x10 => {
            let (input, bcr_count) = be_u32(input)?;
            let (input, (bcr_iv, bcr_ca, bcr_cy, bcr_sq)): (&[u8], (u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(5usize)))
            )(input)?;
            let (input, cp24time_ms) = le_u16(input)?;
            let (input, (cp24time_iv, cp24time_min)): (&[u8], (u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::M_IT_TA_1 {
                    bcr_count,
                    bcr_iv, bcr_ca, bcr_cy, bcr_sq,
                    cp24time_ms,
                    cp24time_iv, cp24time_min
                }
            ))
        }
        0x14 => {
            Ok((
                input,
                IoaTypeEnum::M_PS_NA_1 {}
            ))
        }
        0x15 => {
            let (input, nva_u16) = le_u16(input)?;
            Ok((
                input,
                IoaTypeEnum::M_ME_ND_1 {
                    nva_u16
                }
            ))
        }
        0x1e => {
            let (input, (siq_iv, siq_nt, siq_sb, siq_bl, _, siq_spi)): (&[u8], (u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(3usize), take_bits(1usize)))
            )(input)?;
            let (input, cp56time_ms) = le_u16(input)?;
            let (input, (cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, _, cp56time_month, _, cp56time_year)): (&[u8], (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize), take_bits(1usize), take_bits(7usize), take_bits(3usize), take_bits(5usize), take_bits(4usize), take_bits(4usize), take_bits(1usize), take_bits(7usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::M_SP_TB_1 {
                    siq_iv, siq_nt, siq_sb, siq_bl, siq_spi,
                    cp56time_ms,
                    cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, cp56time_month, cp56time_year
                }
            ))
        }
        0x1f => {
            let (input, (diq_iv, diq_nt, diq_sb, diq_bl, _, diq_dpi)): (&[u8], (u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(2usize), take_bits(2usize)))
            )(input)?;
            let (input, cp56time_ms) = le_u16(input)?;
            let (input, (cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, _, cp56time_month, _, cp56time_year)): (&[u8], (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize), take_bits(1usize), take_bits(7usize), take_bits(3usize), take_bits(5usize), take_bits(4usize), take_bits(4usize), take_bits(1usize), take_bits(7usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::M_DP_TB_1 {
                    diq_iv, diq_nt, diq_sb, diq_bl, diq_dpi,
                    cp56time_ms,
                    cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, cp56time_month, cp56time_year
                }
            ))
        }
        0x20 => {
            let (input, (vti_t, vti_value)): (&[u8], (u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize)))
            )(input)?;
            let (input, (qds_iv, qds_nt, qds_sb, qds_bl, _, qds_ov)): (&[u8], (u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(3usize), take_bits(1usize)))
            )(input)?;
            let (input, cp56time_ms) = le_u16(input)?;
            let (input, (cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, _, cp56time_month, _, cp56time_year)): (&[u8], (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize), take_bits(1usize), take_bits(7usize), take_bits(3usize), take_bits(5usize), take_bits(4usize), take_bits(4usize), take_bits(1usize), take_bits(7usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::M_ST_TB_1 {
                    vti_t, vti_value,
                    qds_iv, qds_nt, qds_sb, qds_bl, qds_ov,
                    cp56time_ms,
                    cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, cp56time_month, cp56time_year
                }
            ))
        }
        0x21 => {
            let (input, bsi) = slice_u8_4(input)?;
            let (input, (qds_iv, qds_nt, qds_sb, qds_bl, _, qds_ov)): (&[u8], (u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(3usize), take_bits(1usize)))
            )(input)?;
            let (input, cp56time_ms) = le_u16(input)?;
            let (input, (cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, _, cp56time_month, _, cp56time_year)): (&[u8], (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize), take_bits(1usize), take_bits(7usize), take_bits(3usize), take_bits(5usize), take_bits(4usize), take_bits(4usize), take_bits(1usize), take_bits(7usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::M_BO_TB_1 {
                    bsi,
                    qds_iv, qds_nt, qds_sb, qds_bl, qds_ov,
                    cp56time_ms,
                    cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, cp56time_month, cp56time_year
                }
            ))
        }
        0x22 => {
            let (input, nva_u16) = le_u16(input)?;
            let (input, (qds_iv, qds_nt, qds_sb, qds_bl, _, qds_ov)): (&[u8], (u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(3usize), take_bits(1usize)))
            )(input)?;
            let (input, cp56time_ms) = le_u16(input)?;
            let (input, (cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, _, cp56time_month, _, cp56time_year)): (&[u8], (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize), take_bits(1usize), take_bits(7usize), take_bits(3usize), take_bits(5usize), take_bits(4usize), take_bits(4usize), take_bits(1usize), take_bits(7usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::M_ME_TD_1 {
                    nva_u16,
                    qds_iv, qds_nt, qds_sb, qds_bl, qds_ov,
                    cp56time_ms,
                    cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, cp56time_month, cp56time_year
                }
            ))
        }
        0x23 => {
            let (input, sva) = be_u16(input)?;
            let (input, (qds_iv, qds_nt, qds_sb, qds_bl, _, qds_ov)): (&[u8], (u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(3usize), take_bits(1usize)))
            )(input)?;
            let (input, cp56time_ms) = le_u16(input)?;
            let (input, (cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, _, cp56time_month, _, cp56time_year)): (&[u8], (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize), take_bits(1usize), take_bits(7usize), take_bits(3usize), take_bits(5usize), take_bits(4usize), take_bits(4usize), take_bits(1usize), take_bits(7usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::M_ME_TE_1 {
                    sva,
                    qds_iv, qds_nt, qds_sb, qds_bl, qds_ov,
                    cp56time_ms,
                    cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, cp56time_month, cp56time_year
                }
            ))
        }
        0x24 => {
            let (input, flt) = be_u32(input)?;
            let (input, (qds_iv, qds_nt, qds_sb, qds_bl, _, qds_ov)): (&[u8], (u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(3usize), take_bits(1usize)))
            )(input)?;
            let (input, cp56time_ms) = le_u16(input)?;
            let (input, (cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, _, cp56time_month, _, cp56time_year)): (&[u8], (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize), take_bits(1usize), take_bits(7usize), take_bits(3usize), take_bits(5usize), take_bits(4usize), take_bits(4usize), take_bits(1usize), take_bits(7usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::M_ME_TF_1 {
                    flt,
                    qds_iv, qds_nt, qds_sb, qds_bl, qds_ov,
                    cp56time_ms,
                    cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, cp56time_month, cp56time_year
                }
            ))
        }
        0x25 => {
            let (input, bcr_count) = be_u32(input)?;
            let (input, (bcr_iv, bcr_ca, bcr_cy, bcr_sq)): (&[u8], (u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(5usize)))
            )(input)?;
            let (input, cp56time_ms) = le_u16(input)?;
            let (input, (cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, _, cp56time_month, _, cp56time_year)): (&[u8], (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize), take_bits(1usize), take_bits(7usize), take_bits(3usize), take_bits(5usize), take_bits(4usize), take_bits(4usize), take_bits(1usize), take_bits(7usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::M_IT_TB_1 {
                    bcr_count,
                    bcr_iv, bcr_ca, bcr_cy, bcr_sq,
                    cp56time_ms,
                    cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, cp56time_month, cp56time_year
                }
            ))
        }
        0x26 => {
            Ok((
                input,
                IoaTypeEnum::M_EP_TD_1 {}
            ))
        }
        0x27 => {
            Ok((
                input,
                IoaTypeEnum::M_EP_TE_1 {}
            ))
        }
        0x28 => {
            Ok((
                input,
                IoaTypeEnum::M_EP_TF_1 {}
            ))
        }
        0x29 => {
            Ok((
                input,
                IoaTypeEnum::S_IT_TC_1 {}
            ))
        }
        0x2d => {
            let (input, (sco_se, sco_qu, _, sco_on)): (&[u8], (u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(5usize), take_bits(1usize), take_bits(1usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::C_SC_NA_1 {
                    sco_se, sco_qu, sco_on
                }
            ))
        }
        0x2e => {
            let (input, (dco_se, dco_qu, dco_on)): (&[u8], (u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(5usize), take_bits(2usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::C_DC_NA_1 {
                    dco_se, dco_qu, dco_on
                }
            ))
        }
        0x2f => {
            let (input, (rco_se, rco_qu, rco_up)): (&[u8], (u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(5usize), take_bits(2usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::C_RC_NA_1 {
                    rco_se, rco_qu, rco_up
                }
            ))
        }
        0x30 => {
            let (input, nva_u16) = le_u16(input)?;
            let (input, (qos_ql, qos_se)): (&[u8], (u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(7usize), take_bits(1usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::C_SE_NA_1 {
                    nva_u16,
                    qos_ql, qos_se
                }
            ))
        }
        0x31 => {
            let (input, sva) = be_u16(input)?;
            let (input, (qos_ql, qos_se)): (&[u8], (u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(7usize), take_bits(1usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::C_SE_NB_1 {
                    sva,
                    qos_ql, qos_se
                }
            ))
        }
        0x32 => {
            let (input, flt) = be_u32(input)?;
            let (input, (qos_ql, qos_se)): (&[u8], (u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(7usize), take_bits(1usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::C_SE_NC_1 {
                    flt,
                    qos_ql, qos_se
                }
            ))
        }
        0x33 => {
            let (input, bsi) = slice_u8_4(input)?;
            Ok((
                input,
                IoaTypeEnum::C_BO_NA_1 {
                    bsi
                }
            ))
        }
        0x3a => {
            let (input, (sco_se, sco_qu, _, sco_on)): (&[u8], (u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(5usize), take_bits(1usize), take_bits(1usize)))
            )(input)?;
            let (input, cp56time_ms) = le_u16(input)?;
            let (input, (cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, _, cp56time_month, _, cp56time_year)): (&[u8], (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize), take_bits(1usize), take_bits(7usize), take_bits(3usize), take_bits(5usize), take_bits(4usize), take_bits(4usize), take_bits(1usize), take_bits(7usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::C_SC_TA_1 {
                    sco_se, sco_qu, sco_on,
                    cp56time_ms,
                    cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, cp56time_month, cp56time_year
                }
            ))
        }
        0x3b => {
            let (input, (dco_se, dco_qu, dco_on)): (&[u8], (u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(5usize), take_bits(2usize)))
            )(input)?;
            let (input, cp56time_ms) = le_u16(input)?;
            let (input, (cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, _, cp56time_month, _, cp56time_year)): (&[u8], (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize), take_bits(1usize), take_bits(7usize), take_bits(3usize), take_bits(5usize), take_bits(4usize), take_bits(4usize), take_bits(1usize), take_bits(7usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::C_DC_TA_1 {
                    dco_se, dco_qu, dco_on,
                    cp56time_ms,
                    cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, cp56time_month, cp56time_year
                }
            ))
        }
        0x3c => {
            let (input, (rco_se, rco_qu, rco_up)): (&[u8], (u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(5usize), take_bits(2usize)))
            )(input)?;
            let (input, cp56time_ms) = le_u16(input)?;
            let (input, (cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, _, cp56time_month, _, cp56time_year)): (&[u8], (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize), take_bits(1usize), take_bits(7usize), take_bits(3usize), take_bits(5usize), take_bits(4usize), take_bits(4usize), take_bits(1usize), take_bits(7usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::C_RC_TA_1 {
                    rco_se, rco_qu, rco_up,
                    cp56time_ms,
                    cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, cp56time_month, cp56time_year
                }
            ))
        }
        0x3d => {
            let (input, nva_u16) = le_u16(input)?;
            let (input, (qos_ql, qos_se)): (&[u8], (u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(7usize), take_bits(1usize)))
            )(input)?;
            let (input, cp56time_ms) = le_u16(input)?;
            let (input, (cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, _, cp56time_month, _, cp56time_year)): (&[u8], (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize), take_bits(1usize), take_bits(7usize), take_bits(3usize), take_bits(5usize), take_bits(4usize), take_bits(4usize), take_bits(1usize), take_bits(7usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::C_SE_TA_1 {
                    nva_u16,
                    qos_ql, qos_se,
                    cp56time_ms,
                    cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, cp56time_month, cp56time_year
                }
            ))
        }
        0x3e => {
            let (input, sva) = be_u16(input)?;
            let (input, (qos_ql, qos_se)): (&[u8], (u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(7usize), take_bits(1usize)))
            )(input)?;
            let (input, cp56time_ms) = le_u16(input)?;
            let (input, (cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, _, cp56time_month, _, cp56time_year)): (&[u8], (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize), take_bits(1usize), take_bits(7usize), take_bits(3usize), take_bits(5usize), take_bits(4usize), take_bits(4usize), take_bits(1usize), take_bits(7usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::C_SE_TB_1 {
                    sva,
                    qos_ql, qos_se,
                    cp56time_ms,
                    cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, cp56time_month, cp56time_year
                }
            ))
        }
        0x3f => {
            let (input, flt) = be_u32(input)?;
            let (input, (qos_ql, qos_se)): (&[u8], (u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(7usize), take_bits(1usize)))
            )(input)?;
            let (input, cp56time_ms) = le_u16(input)?;
            let (input, (cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, _, cp56time_month, _, cp56time_year)): (&[u8], (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize), take_bits(1usize), take_bits(7usize), take_bits(3usize), take_bits(5usize), take_bits(4usize), take_bits(4usize), take_bits(1usize), take_bits(7usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::C_SE_TC_1 {
                    flt,
                    qos_ql, qos_se,
                    cp56time_ms,
                    cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, cp56time_month, cp56time_year
                }
            ))
        }
        0x40 => {
            let (input, bsi) = slice_u8_4(input)?;
            let (input, (qos_ql, qos_se)): (&[u8], (u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(7usize), take_bits(1usize)))
            )(input)?;
            let (input, cp56time_ms) = le_u16(input)?;
            let (input, (cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, _, cp56time_month, _, cp56time_year)): (&[u8], (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize), take_bits(1usize), take_bits(7usize), take_bits(3usize), take_bits(5usize), take_bits(4usize), take_bits(4usize), take_bits(1usize), take_bits(7usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::C_BO_TA_1 {
                    bsi,
                    qos_ql, qos_se,
                    cp56time_ms,
                    cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, cp56time_month, cp56time_year
                }
            ))
        }
        0x46 => {
            let (input, (coi_r, coi_i)): (&[u8], (u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(7usize), take_bits(1usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::M_EI_NA_1 {
                    coi_r, coi_i
                }
            ))
        }
        0x51 => {
            Ok((
                input,
                IoaTypeEnum::S_CH_NA_1 {}
            ))
        }
        0x52 => {
            Ok((
                input,
                IoaTypeEnum::S_RP_NA_1 {}
            ))
        }
        0x53 => {
            Ok((
                input,
                IoaTypeEnum::S_AR_NA_1 {}
            ))
        }
        0x54 => {
            Ok((
                input,
                IoaTypeEnum::S_KR_NA_1 {}
            ))
        }
        0x55 => {
            Ok((
                input,
                IoaTypeEnum::S_KS_NA_1 {}
            ))
        }
        0x56 => {
            Ok((
                input,
                IoaTypeEnum::S_KC_NA_1 {}
            ))
        }
        0x57 => {
            Ok((
                input,
                IoaTypeEnum::S_ER_NA_1 {}
            ))
        }
        0x5a => {
            Ok((
                input,
                IoaTypeEnum::S_US_NA_1 {}
            ))
        }
        0x5b => {
            Ok((
                input,
                IoaTypeEnum::S_UQ_NA_1 {}
            ))
        }
        0x5c => {
            Ok((
                input,
                IoaTypeEnum::S_UR_NA_1 {}
            ))
        }
        0x5d => {
            Ok((
                input,
                IoaTypeEnum::S_UK_NA_1 {}
            ))
        }
        0x5e => {
            Ok((
                input,
                IoaTypeEnum::S_UA_NA_1 {}
            ))
        }
        0x5f => {
            Ok((
                input,
                IoaTypeEnum::S_UC_NA_1 {}
            ))
        }
        0x64 => {
            let (input, qoi) = u8(input)?;
            Ok((
                input,
                IoaTypeEnum::C_IC_NA_1 {
                    qoi
                }
            ))
        }
        0x65 => {
            let (input, (qcc_frz, qcc_rqt)): (&[u8], (u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(2usize), take_bits(6usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::C_CI_NA_1 {
                    qcc_frz, qcc_rqt
                }
            ))
        }
        0x66 => {
            Ok((
                input,
                IoaTypeEnum::C_RD_NA_1 {}
            ))
        }
        0x67 => {
            let (input, cp56time_ms) = le_u16(input)?;
            let (input, (cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, _, cp56time_month, _, cp56time_year)): (&[u8], (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(7usize), take_bits(1usize), take_bits(7usize), take_bits(3usize), take_bits(5usize), take_bits(4usize), take_bits(4usize), take_bits(1usize), take_bits(7usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::C_CS_NA_1 {
                    cp56time_ms,
                    cp56time_iv, cp56time_min, cp56time_su, cp56time_hour, cp56time_dow, cp56time_day, cp56time_month, cp56time_year
                }
            ))
        }
        0x69 => {
            let (input, qrp) = u8(input)?;
            Ok((
                input,
                IoaTypeEnum::C_RP_NA_1 {
                    qrp
                }
            ))
        }
        0x6b => {
            Ok((
                input,
                IoaTypeEnum::C_TS_TA_1 {}
            ))
        }
        0x6e => {
            let (input, nva_u16) = le_u16(input)?;
            let (input, (qpm_pop, qpm_lpc, qpm_kpa)): (&[u8], (u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(6usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::P_ME_NA_1 {
                    nva_u16,
                    qpm_pop, qpm_lpc, qpm_kpa
                }
            ))
        }
        0x6f => {
            let (input, sva) = be_u16(input)?;
            let (input, (qpm_pop, qpm_lpc, qpm_kpa)): (&[u8], (u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(6usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::P_ME_NB_1 {
                    sva,
                    qpm_pop, qpm_lpc, qpm_kpa
                }
            ))
        }
        0x70 => {
            let (input, flt) = be_u32(input)?;
            let (input, (qpm_pop, qpm_lpc, qpm_kpa)): (&[u8], (u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(1usize), take_bits(1usize), take_bits(6usize)))
            )(input)?;
            Ok((
                input,
                IoaTypeEnum::P_ME_NC_1 {
                    flt,
                    qpm_pop, qpm_lpc, qpm_kpa
                }
            ))
        }
        0x71 => {
            Ok((
                input,
                IoaTypeEnum::P_AC_NA_1 {}
            ))
        }
        0x78 => {
            Ok((
                input,
                IoaTypeEnum::F_FR_NA_1 {}
            ))
        }
        0x79 => {
            Ok((
                input,
                IoaTypeEnum::F_SR_NA_1 {}
            ))
        }
        0x7a => {
            Ok((
                input,
                IoaTypeEnum::F_SC_NA_1 {}
            ))
        }
        0x7b => {
            Ok((
                input,
                IoaTypeEnum::F_LS_NA_1 {}
            ))
        }
        0x7c => {
            Ok((
                input,
                IoaTypeEnum::F_AF_NA_1 {}
            ))
        }
        0x7d => {
            Ok((
                input,
                IoaTypeEnum::F_SG_NA_1 {}
            ))
        }
        0x7e => {
            Ok((
                input,
                IoaTypeEnum::F_DR_NA_1 {}
            ))
        }
        0x7f => {
            Ok((
                input,
                IoaTypeEnum::F_SC_NB_1 {}
            ))
        }
        _ =>  Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }?;
    Ok((input, ioa_type_enum))
}

pub fn parse_ioa(input: &[u8], type_id: u8) -> IResult<&[u8], Ioa> {
    let (input, ioa) = le_u24(input)?;
    let (input, ioa_type_enum) = parse_ioa_type_enum(input, type_id)?;
    Ok((
        input,
        Ioa {
            ioa,
            ioa_type_enum
        }
    ))
}

pub fn parse_iec_asdu(input: &[u8]) -> IResult<&[u8], IecAsdu> {
    let (input, type_id) = u8(input)?;
    let (input, (sq, num_ix, test, negative, cause_tx)): (&[u8], (u8, u8, u8, u8, u8))  = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
        tuple((take_bits(1usize), take_bits(7usize), take_bits(1usize), take_bits(1usize), take_bits(6usize)))
    )(input)?;
    let (input, oa) = u8(input)?;
    let (input, addr) = le_u16(input)?;
    /* LimitedCountVecLoopField Start */
    let mut ioa_array = Vec::new();
    let mut _ioa_array: Ioa;
    let mut input = input;
    for _ in 0..(num_ix as usize) {
        (input, _ioa_array) = parse_ioa(input, type_id)?;
        ioa_array.push(_ioa_array);
    }
    let input = input;
    /* LimitedCountVecLoopField End. */
    Ok((
        input,
        IecAsdu {
            type_id,
            sq, num_ix, test, negative, cause_tx,
            oa,
            addr,
            ioa_array
        }
    ))
}



pub fn parse_type_block(input: &[u8], apci_txid_tmp: u16, apci_rxid_tmp: u16) -> IResult<&[u8], TypeBlock> {
    if apci_txid_tmp & 0x01u16 == 0x00u16 {
        let type104: u8 = 0x00;
        let apci_txid = (apci_txid_tmp >> 1).try_into().unwrap();
        let apci_rxid = (apci_rxid_tmp >> 1).try_into().unwrap();
        let (input, iec_asdu) = parse_iec_asdu(input)?;
        Ok((
            input,
            TypeBlock::TypeI {
                type104,
                apci_txid,
                apci_rxid,
                iec_asdu
            }
        ))
    }
    else if apci_txid_tmp & 0x03u16 == 0x01u16 {
        let type104: u8 = 0x01;
        let apci_rxid = (apci_rxid_tmp >> 1).try_into().unwrap();
        Ok((
            input,
            TypeBlock::TypeS {
                type104,
                apci_rxid
            }
        ))
    }
    else if apci_txid_tmp & 0x03u16 == 0x03u16 {
        let type104: u8 = 0x03;
        let apci_utype = (apci_txid_tmp >> 2).try_into().unwrap();
        Ok((
            input,
            TypeBlock::TypeU {
                type104,
                apci_utype
            }
        ))
    }
    else {
        return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
    }
}

pub fn parse_iec104_block(input: &[u8]) -> IResult<&[u8], Iec104Block> {
    let (input, start) = u8(input)?;
    if !(start == 0x68) {
        return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
    }
    let (input, apdu_len) = u8(input)?;
    let (input, apci_txid_tmp) = le_u16(input)?;
    let (input, apci_rxid_tmp) = le_u16(input)?;
    let (input, type_block) = parse_type_block(input, apci_txid_tmp, apci_rxid_tmp)?;
    Ok((
        input,
        Iec104Block {
            start,
            apdu_len,
            type_block
        }
    ))
}