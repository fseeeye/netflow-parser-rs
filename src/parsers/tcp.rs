use nom::bits::bits;
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::take;
use nom::number::complete::{be_u16, be_u32};
use nom::sequence::tuple;

use crate::errors::ParseError;
use crate::layer::{LinkLayer, NetworkLayer, TransportLayer};
use crate::packet_level::{L3Packet, L4Packet};
use crate::packet_quin::{QuinPacket, QuinPacketOptions};
use crate::LayerType;

use super::{parse_fins_tcp_req_layer, parse_fins_tcp_rsp_layer, parse_l4_eof_layer, parse_modbus_req_layer, parse_modbus_rsp_layer};

// TCP Header Format
//
//
//     0                   1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 0  |          Source Port          |       Destination Port        |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 4  |                        Sequence Number                        |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 8  |                    Acknowledgment Number                      |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |  Data |           |U|A|P|R|S|F|                               |
// 12 | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
//    |       |           |G|K|H|T|N|N|                               |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 16 |           Checksum            |         Urgent Pointer        |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 20 |                                               |               |
//  - |                    Options                    |    Padding    |
// 60 |                                               |               |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                             data                              |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// TCP Flags:
//    URG:  Urgent Pointer field significant
//    ACK:  Acknowledgment field significant
//    PSH:  Push Function
//    RST:  Reset the connection
//    SYN:  Synchronize sequence numbers
//    FIN:  No more data from sender
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct TcpHeader<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub header_length: u8,
    pub reserved: u8,
    pub flags: u16,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: Option<&'a [u8]>,
}

pub fn parse_tcp_header(input: &[u8]) -> nom::IResult<&[u8], TcpHeader> {
    let (input, src_port) = be_u16(input)?;
    let (input, dst_port) = be_u16(input)?;
    let (input, seq) = be_u32(input)?;
    let (input, ack) = be_u32(input)?;
    let (input, (header_length, reserved, flags)) =
        bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
            take_bits(4usize),
            take_bits(3usize),
            take_bits(9usize),
        )))(input)?;
    let (input, window_size) = be_u16(input)?;
    let (input, checksum) = be_u16(input)?;
    let (input, urgent_pointer) = be_u16(input)?;
    let (input, options) = if (header_length * 4) > 20 {
        let (input, options) = take(header_length * 4 - 20)(input)?;
        Ok((input, Some(options)))
    } else {
        Ok((input, None))
    }?;

    Ok((
        input,
        TcpHeader {
            src_port,
            dst_port,
            seq,
            ack,
            header_length,
            reserved,
            flags,
            window_size,
            checksum,
            urgent_pointer,
            options,
        },
    ))
}

pub(crate) fn parse_tcp_layer<'a>(
    input: &'a [u8],
    link_layer: LinkLayer,
    network_layer: NetworkLayer<'a>,
    options: QuinPacketOptions,
) -> QuinPacket<'a> {
    let current_layertype = LayerType::Tcp;

    let (input, tcp_header) = match parse_tcp_header(input) {
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
        let transport_layer = TransportLayer::Tcp(tcp_header);
        return QuinPacket::L4(L4Packet {
            link_layer,
            network_layer,
            transport_layer,
            error: None,
            remain: input,
        });
    }

    if input.len() == 0 {
        let transport_layer = TransportLayer::Tcp(tcp_header);
        return parse_l4_eof_layer(input, link_layer, network_layer, transport_layer, options);
    }
    match tcp_header.src_port {
        502 => {
            let transport_layer = TransportLayer::Tcp(tcp_header);
            parse_modbus_rsp_layer(input, link_layer, network_layer, transport_layer, options)
        }
        9600 => {
            let transport_layer = TransportLayer::Tcp(tcp_header);
            parse_fins_tcp_rsp_layer(input, link_layer, network_layer, transport_layer, options)
        }
        _ => match tcp_header.dst_port {
            502 => {
                let transport_layer = TransportLayer::Tcp(tcp_header);
                parse_modbus_req_layer(input, link_layer, network_layer, transport_layer, options)
            }
            9600 => {
                let transport_layer = TransportLayer::Tcp(tcp_header);
                parse_fins_tcp_req_layer(input, link_layer, network_layer, transport_layer, options)
            }
            _ => {
                let transport_layer = TransportLayer::Tcp(tcp_header);
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
