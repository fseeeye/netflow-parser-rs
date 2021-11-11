use crate::errors::ParseError;
use crate::layer::{ApplicationLayer, LinkLayer, NetworkLayer, TransportLayer};
use crate::packet::{QuinPacket, QuinPacketOptions, L2Packet, L3Packet, L4Packet, L5Packet};

#[derive(Debug, PartialEq, Clone)]
pub struct EofHeader;

pub(crate) fn parse_l2_eof_layer<'a>(
    input: &'a [u8],
    link_layer: LinkLayer,
    _options: &QuinPacketOptions,
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
    network_layer: NetworkLayer<'a>,
    _options: &QuinPacketOptions,
) -> QuinPacket<'a> {
    if input.len() == 0 {
        return QuinPacket::L3(L3Packet {
            link_layer,
            network_layer,
            error: None,
            remain: input,
        });
    } else {
        return QuinPacket::L3(L3Packet {
            link_layer,
            network_layer,
            error: Some(ParseError::NotEndPayload),
            remain: input,
        });
    }
}

pub(crate) fn parse_l4_eof_layer<'a>(
    input: &'a [u8],
    link_layer: LinkLayer,
    network_layer: NetworkLayer<'a>,
    transport_layer: TransportLayer<'a>,
    _options: &QuinPacketOptions,
) -> QuinPacket<'a> {
    if input.len() == 0 {
        return QuinPacket::L4(L4Packet {
            link_layer,
            network_layer,
            transport_layer,
            error: None,
            remain: input,
        });
    } else {
        return QuinPacket::L4(L4Packet {
            link_layer,
            network_layer,
            transport_layer,
            error: Some(ParseError::NotEndPayload),
            remain: input,
        });
    }
}

pub(crate) fn parse_l5_eof_layer<'a>(
    input: &'a [u8],
    link_layer: LinkLayer,
    network_layer: NetworkLayer<'a>,
    transport_layer: TransportLayer<'a>,
    application_layer: ApplicationLayer<'a>,
    _options: &QuinPacketOptions,
) -> QuinPacket<'a> {
    if input.len() == 0 {
        return QuinPacket::L5(L5Packet {
            link_layer,
            network_layer,
            transport_layer,
            application_layer,
            error: None,
            remain: input,
        });
    } else {
        return QuinPacket::L5(L5Packet {
            link_layer,
            network_layer,
            transport_layer,
            application_layer,
            error: Some(ParseError::NotEndPayload),
            remain: input,
        });
    }
}
