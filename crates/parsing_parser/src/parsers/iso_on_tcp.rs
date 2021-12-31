use nom::combinator::peek;
use nom::number::complete::{be_u16, u8};
use nom::IResult;
use tracing::error;

use crate::errors::ParseError;
use crate::layer::{ApplicationLayer, LinkLayer, NetworkLayer, TransportLayer};
use crate::packet::{L4Packet, L5Packet, QuinPacket, QuinPacketOptions};

use super::{parse_l5_eof_layer, parse_mms_layer, parse_s7comm_layer};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IsoOnTcpHeader {
    pub tpkt: Tpkt,
    pub cotp: Cotp,
}

pub fn parse_iso_header(input: &[u8]) -> IResult<&[u8], IsoOnTcpHeader> {
    let (input, tpkt) = parse_tpkt(input)?;
    let (input, cotp) = parse_cotp(input)?;
    Ok((input, IsoOnTcpHeader { tpkt, cotp }))
}

pub fn parse_iso_on_tcp_layer<'a>(
    input: &'a [u8],
    link_layer: LinkLayer,
    network_layer: NetworkLayer<'a>,
    transport_layer: TransportLayer<'a>,
    options: &QuinPacketOptions,
) -> QuinPacket<'a> {
    let (input, iso_header) = match parse_iso_header(input) {
        Ok(o) => o,
        Err(e) => {
            error!(
                target: "PARSER(iso_on_tcp::parse_iso_on_tcp_layer)",
                error = ?e
            );
            return QuinPacket::L4(L4Packet {
                link_layer,
                network_layer,
                transport_layer,
                error: Some(ParseError::ParsingHeader),
                remain: input,
            });
        }
    };

    match iso_header.cotp.cotp_pdu {
        CotpPdu::Data { .. } => {
            let (input, next_iso_pdu_type) = match peek(u8)(input) {
                Ok(o) => o,
                Err(nom::Err::Error((_, _))) => {
                    let application_layer = ApplicationLayer::IsoOnTcp(iso_header);
                    return QuinPacket::L5(L5Packet {
                        link_layer,
                        network_layer,
                        transport_layer,
                        application_layer,
                        error: None,
                        remain: input,
                    });
                }
                _ => {
                    let application_layer = ApplicationLayer::IsoOnTcp(iso_header);
                    return QuinPacket::L5(L5Packet {
                        link_layer,
                        network_layer,
                        transport_layer,
                        application_layer,
                        error: Some(ParseError::ParsingPayload),
                        remain: input,
                    });
                }
            };
            match next_iso_pdu_type {
                0x32 => {
                    parse_s7comm_layer(input, link_layer, network_layer, transport_layer, options)
                }
                _ => parse_mms_layer(input, link_layer, network_layer, transport_layer, options),
            }
        }
        _ => {
            let application_layer = ApplicationLayer::IsoOnTcp(iso_header);
            parse_l5_eof_layer(
                input,
                link_layer,
                network_layer,
                transport_layer,
                application_layer,
                options,
            )
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Tpkt {
    pub version: u8,
    pub reserved: u8,
    pub length: u16,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CotpPdu {
    ConnectRequest {
        destination_reference: u16,
        source_reference: u16,
        bit_mask: u8,
        parameter_src_tsap: u8,
        parameter_src_length: u8,
        source_tsap: u16,
        parameter_dst_tsap: u8,
        parameter_dst_length: u8,
        destination_tsap: u16,
    },
    ConnectConfirmLong {
        destination_reference: u16,
        source_reference: u16,
        bit_mask: u8,
        parameter_src_tsap: u8,
        parameter_src_length: u8,
        source_tsap: u16,
        parameter_dst_tsap: u8,
        parameter_dst_length: u8,
        destination_tsap: u16,
        parameter_tpdu_size: u8,
        parameter_tpdu_length: u8,
        tpdu_size: u8,
    },
    ConnectConfirmShort {
        destination_reference: u16,
        source_reference: u16,
        bit_mask: u8,
        parameter_code: u8,
        parameter_length: u8,
        tpdu_size: u8,
    },
    Data {
        bit_mask: u8,
    },
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Cotp {
    pub length: u8,
    pub pdu_type: u8,
    pub cotp_pdu: CotpPdu,
}

pub fn parse_tpkt(input: &[u8]) -> IResult<&[u8], Tpkt> {
    if input.first() != Some(&0x03) {
        let length = match (input.len() + 4).try_into() {
            Ok(o) => o,
            Err(_) => 0xffff,
        };
        return Ok((
            input,
            Tpkt {
                version: 3,
                reserved: 0,
                length,
            },
        ));
    }

    let (input, version) = u8(input)?;
    let (input, reserved) = u8(input)?;
    let (input, length) = be_u16(input)?;
    Ok((
        input,
        Tpkt {
            version,
            reserved,
            length,
        },
    ))
}

fn parse_connect_request(input: &[u8]) -> IResult<&[u8], CotpPdu> {
    let (input, destination_reference) = be_u16(input)?;
    let (input, source_reference) = be_u16(input)?;
    let (input, bit_mask) = u8(input)?;
    let (input, parameter_src_tsap) = u8(input)?;
    let (input, parameter_src_length) = u8(input)?;
    let (input, source_tsap) = be_u16(input)?;
    let (input, parameter_dst_tsap) = u8(input)?;
    let (input, parameter_dst_length) = u8(input)?;
    let (input, destination_tsap) = be_u16(input)?;
    Ok((
        input,
        CotpPdu::ConnectRequest {
            destination_reference,
            source_reference,
            bit_mask,
            parameter_src_tsap,
            parameter_src_length,
            source_tsap,
            parameter_dst_tsap,
            parameter_dst_length,
            destination_tsap,
        },
    ))
}

fn parse_connect_confirm(input: &[u8], length: u8) -> IResult<&[u8], CotpPdu> {
    if length == 17 {
        let (input, destination_reference) = be_u16(input)?;
        let (input, source_reference) = be_u16(input)?;
        let (input, bit_mask) = u8(input)?;
        let (input, parameter_src_tsap) = u8(input)?;
        let (input, parameter_src_length) = u8(input)?;
        let (input, source_tsap) = be_u16(input)?;
        let (input, parameter_dst_tsap) = u8(input)?;
        let (input, parameter_dst_length) = u8(input)?;
        let (input, destination_tsap) = be_u16(input)?;
        let (input, parameter_tpdu_size) = u8(input)?;
        let (input, parameter_tpdu_length) = u8(input)?;
        let (input, tpdu_size) = u8(input)?;
        Ok((
            input,
            CotpPdu::ConnectConfirmLong {
                destination_reference,
                source_reference,
                bit_mask,
                parameter_src_tsap,
                parameter_src_length,
                source_tsap,
                parameter_dst_tsap,
                parameter_dst_length,
                destination_tsap,
                parameter_tpdu_size,
                parameter_tpdu_length,
                tpdu_size,
            },
        ))
    } else {
        let (input, destination_reference) = be_u16(input)?;
        let (input, source_reference) = be_u16(input)?;
        let (input, bit_mask) = u8(input)?;
        let (input, parameter_code) = u8(input)?;
        let (input, parameter_length) = u8(input)?;
        let (input, tpdu_size) = u8(input)?;

        Ok((
            input,
            CotpPdu::ConnectConfirmShort {
                destination_reference,
                source_reference,
                bit_mask,
                parameter_code,
                parameter_length,
                tpdu_size,
            },
        ))
    }
}

fn parse_cotp_pdu_data(input: &[u8]) -> IResult<&[u8], CotpPdu> {
    let (input, bit_mask) = u8(input)?;
    Ok((input, CotpPdu::Data { bit_mask }))
}

pub fn parse_cotp_pdu(input: &[u8], pdu_type: u8, length: u8) -> IResult<&[u8], CotpPdu> {
    let (input, cotp_pdu) = match pdu_type {
        0xe0 => parse_connect_request(input),
        0xd0 => parse_connect_confirm(input, length),
        0xf0 => parse_cotp_pdu_data(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, cotp_pdu))
}

pub fn parse_cotp(input: &[u8]) -> IResult<&[u8], Cotp> {
    let (input, length) = u8(input)?;
    let (input, pdu_type) = u8(input)?;
    let (input, cotp_pdu) = parse_cotp_pdu(input, pdu_type, length)?;
    Ok((
        input,
        Cotp {
            length,
            pdu_type,
            cotp_pdu,
        },
    ))
}
