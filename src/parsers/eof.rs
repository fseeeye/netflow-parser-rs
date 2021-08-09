use crate::errors::ParseError;
use crate::layer::{ApplicationLayer, LinkLayer, NetworkLayer, TransportLayer};
use crate::packet_level::{L2Packet, L3Packet, L4Packet, L5Packet};
use crate::packet_quin::{QuinPacket, QuinPacketOptions};

#[derive(Debug, PartialEq, Clone)]
pub struct EofHeader;

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
