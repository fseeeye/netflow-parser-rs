use nom::combinator::eof;

use crate::errors::ParseError;
use crate::layer::{ApplicationLayer, LinkLayer, NetworkLayer, TransportLayer};
use crate::packet_level::{L2Packet, L3Packet, L4Packet, L5Packet};
use crate::packet_quin::{QuinPacket, QuinPacketOptions};
use crate::{Layer, LayerType};

#[derive(Debug, PartialEq, Clone)]
pub struct EofHeader;

pub(crate) fn parse_eof_fatlayer(input: &[u8]) -> nom::IResult<&[u8], (Layer, Option<LayerType>)> {
    let (input, header) = parse_eof_header(input)?;
    let next = parse_eof_payload(input, &header);
    let layer = Layer::Eof(header);

    Ok((input, (layer, next)))
}

fn parse_eof_header(input: &[u8]) -> nom::IResult<&[u8], EofHeader> {
    Ok((input, EofHeader {}))
}

fn parse_eof_payload(input: &[u8], _header: &EofHeader) -> Option<LayerType> {
    match eof(input) {
        Ok((_input, _nullstr)) => None,
        Err(nom::Err::Error((_input, _))) => Some(LayerType::Error(ParseError::NotEndPayload)),
        _ => Some(LayerType::Error(ParseError::ParsingPayload)),
    }
}

pub(crate) fn parse_l2_eof_layer<'a>(
    input: &'a [u8],
    link_layer: LinkLayer,
    _options: QuinPacketOptions,
) -> QuinPacket<'a> {
    if input.len() == 0 {
        return QuinPacket::L2(L2Packet {
            link_layer,
            error: None,
            remain: input,
        });
    } else {
        return QuinPacket::L2(L2Packet {
            link_layer,
            error: Some(ParseError::NotEndPayload),
            remain: input,
        });
    }
}

pub(crate) fn parse_l3_eof_layer<'a>(
    input: &'a [u8],
    link_layer: LinkLayer,
    net_layer: NetworkLayer<'a>,
    _options: QuinPacketOptions,
) -> QuinPacket<'a> {
    if input.len() == 0 {
        return QuinPacket::L3(L3Packet {
            link_layer,
            net_layer,
            error: None,
            remain: input,
        });
    } else {
        return QuinPacket::L3(L3Packet {
            link_layer,
            net_layer,
            error: Some(ParseError::NotEndPayload),
            remain: input,
        });
    }
}

pub(crate) fn parse_l4_eof_layer<'a>(
    input: &'a [u8],
    link_layer: LinkLayer,
    net_layer: NetworkLayer<'a>,
    trans_layer: TransportLayer<'a>,
    _options: QuinPacketOptions,
) -> QuinPacket<'a> {
    if input.len() == 0 {
        return QuinPacket::L4(L4Packet {
            link_layer,
            net_layer,
            trans_layer,
            error: None,
            remain: input,
        });
    } else {
        return QuinPacket::L4(L4Packet {
            link_layer,
            net_layer,
            trans_layer,
            error: Some(ParseError::NotEndPayload),
            remain: input,
        });
    }
}

pub(crate) fn parse_l5_eof_layer<'a>(
    input: &'a [u8],
    link_layer: LinkLayer,
    net_layer: NetworkLayer<'a>,
    trans_layer: TransportLayer<'a>,
    app_layer: ApplicationLayer<'a>,
    _options: QuinPacketOptions,
) -> QuinPacket<'a> {
    if input.len() == 0 {
        return QuinPacket::L5(L5Packet {
            link_layer,
            net_layer,
            trans_layer,
            app_layer,
            error: None,
            remain: input,
        });
    } else {
        return QuinPacket::L5(L5Packet {
            link_layer,
            net_layer,
            trans_layer,
            app_layer,
            error: Some(ParseError::NotEndPayload),
            remain: input,
        });
    }
}
