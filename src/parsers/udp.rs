use nom::number::complete::be_u16;

use crate::errors::ParseError;
use crate::layer::{LinkLayer, NetworkLayer, TransportLayer};
use crate::layer_type::TransportLayerType;
use crate::packet_level::{L3Packet, L4Packet};
use crate::packet_quin::{QuinPacket, QuinPacketOptions};
use crate::LayerType;

use super::{parse_fins_udp_req_layer, parse_fins_udp_rsp_layer, parse_l4_eof_layer, parse_modbus_req_layer, parse_modbus_rsp_layer};

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

pub fn parse_udp_header(input: &[u8]) -> nom::IResult<&[u8], UdpHeader> {
    let (input, src_port) = be_u16(input)?;
    let (input, dst_port) = be_u16(input)?;
    let (input, length) = be_u16(input)?;
    let (input, checksum) = be_u16(input)?;
    Ok((
        input,
        UdpHeader {
            src_port,
            dst_port,
            length,
            checksum,
        },
    ))
}

pub(crate) fn parse_udp_layer<'a>(
    input: &'a [u8],
    link_layer: LinkLayer,
    network_layer: NetworkLayer<'a>,
    options: QuinPacketOptions,
) -> QuinPacket<'a> {
    let current_layertype = LayerType::Transport(TransportLayerType::Udp);

    let (input, udp_header) = match parse_udp_header(input) {
        Ok(o) => o,
        Err(_e) => {
            return QuinPacket::L3(L3Packet {
                link_layer,
                network_layer,
                error: Some(ParseError::ParsingHeader),
                remain: input,
            })
        }
    };

    if Some(current_layertype) == options.stop {
        let transport_layer = TransportLayer::Udp(udp_header);
        return QuinPacket::L4(L4Packet {
            link_layer,
            network_layer,
            transport_layer,
            error: None,
            remain: input,
        });
    }

    if input.len() == 0 {
        let transport_layer = TransportLayer::Udp(udp_header);
        return parse_l4_eof_layer(input, link_layer, network_layer, transport_layer, options);
    }
    match udp_header.src_port {
        502 => {
            let transport_layer = TransportLayer::Udp(udp_header);
            parse_modbus_rsp_layer(input, link_layer, network_layer, transport_layer, options)
        }
        9600 => {
            let transport_layer = TransportLayer::Udp(udp_header);
            parse_fins_udp_rsp_layer(input, link_layer, network_layer, transport_layer, options)
        }
        _ => match udp_header.dst_port {
            502 => {
                let transport_layer = TransportLayer::Udp(udp_header);
                parse_modbus_req_layer(input, link_layer, network_layer, transport_layer, options)
            }
            9600 => {
                let transport_layer = TransportLayer::Udp(udp_header);
                parse_fins_udp_req_layer(input, link_layer, network_layer, transport_layer, options)
            }
            _ => {
                let transport_layer = TransportLayer::Udp(udp_header);
                return QuinPacket::L4(L4Packet {
                    link_layer,
                    network_layer,
                    transport_layer,
                    error: Some(ParseError::UnknownPayload),
                    remain: input,
                });
            }
        },
    }
}
