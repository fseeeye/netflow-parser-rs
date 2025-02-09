use nom::bits::bits;
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::take;
use nom::number::complete::{be_u16, be_u32};
use nom::sequence::tuple;

use crate::errors::ParseError;
use crate::layer::{LinkLayer, NetworkLayer, TransportLayer};
use crate::packet::{L3Packet, L4Packet, QuinPacket, QuinPacketOptions};
use crate::protocol::TransportProtocol;
use crate::ProtocolType;

use super::{
    parse_bacnet_layer, parse_dnp3_layer, parse_fins_tcp_req_layer, parse_fins_tcp_rsp_layer,
    parse_http_layer, parse_iec104_layer, parse_iso_on_tcp_layer, parse_l4_eof_layer,
    parse_modbus_req_layer, parse_modbus_rsp_layer, parse_opcua_layer,
};

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
    pub padding: Option<&'a [u8]>,
    pub payload: &'a [u8],
}

pub fn parse_tcp_header(input: &[u8]) -> nom::IResult<&[u8], TcpHeader> {
    let tcp_len = input.len();
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
        (input, Some(options))
    } else {
        (input, None)
    };
    let (input, padding) = if tcp_len == 26 {
        ([].as_slice(), Some(input))
    } else {
        (input, None)
    };
    let payload = input;

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
            padding,
            payload,
        },
    ))
}

pub fn parse_tcp_layer<'a>(
    input: &'a [u8],
    link_layer: LinkLayer,
    network_layer: NetworkLayer<'a>,
    options: &QuinPacketOptions,
) -> QuinPacket<'a> {
    let current_prototype = ProtocolType::Transport(TransportProtocol::Tcp);

    let (input, tcp_header) = match parse_tcp_header(input) {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(
                target: "PARSER(tcp::parse_tcp_layer)",
                error = ?e
            );

            let offset = match e {
                nom::Err::Error(error) => input.len() - error.input.len(),
                _ => usize::MAX
            };

            return QuinPacket::L3(L3Packet {
                link_layer,
                network_layer,
                error: Some(ParseError::ParsingHeader{
                    protocol: current_prototype,
                    offset
                }),
                remain: input,
            })
        }
    };

    if Some(current_prototype) == options.stop {
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
        80 => {
            let transport_layer = TransportLayer::Tcp(tcp_header);
            parse_http_layer(input, link_layer, network_layer, transport_layer, options)
        }
        102 => {
            let transport_layer = TransportLayer::Tcp(tcp_header);
            parse_iso_on_tcp_layer(input, link_layer, network_layer, transport_layer, options)
        }
        502 => {
            let transport_layer = TransportLayer::Tcp(tcp_header);
            parse_modbus_rsp_layer(input, link_layer, network_layer, transport_layer, options)
        }
        2404 => {
            let transport_layer = TransportLayer::Tcp(tcp_header);
            parse_iec104_layer(input, link_layer, network_layer, transport_layer, options)
        }
        9600 => {
            let transport_layer = TransportLayer::Tcp(tcp_header);
            parse_fins_tcp_rsp_layer(input, link_layer, network_layer, transport_layer, options)
        }
        12001 | 48400 => {
            let transport_layer = TransportLayer::Tcp(tcp_header);
            parse_opcua_layer(input, link_layer, network_layer, transport_layer, options)
        }
        20000 => {
            let transport_layer = TransportLayer::Tcp(tcp_header);
            parse_dnp3_layer(input, link_layer, network_layer, transport_layer, options)
        }
        47808 => {
            let transport_layer = TransportLayer::Tcp(tcp_header);
            parse_bacnet_layer(input, link_layer, network_layer, transport_layer, options)
        }
        _ => match tcp_header.dst_port {
            80 => {
                let transport_layer = TransportLayer::Tcp(tcp_header);
                parse_http_layer(input, link_layer, network_layer, transport_layer, options)
            }
            102 => {
                let transport_layer = TransportLayer::Tcp(tcp_header);
                parse_iso_on_tcp_layer(input, link_layer, network_layer, transport_layer, options)
            }
            502 => {
                let transport_layer = TransportLayer::Tcp(tcp_header);
                parse_modbus_req_layer(input, link_layer, network_layer, transport_layer, options)
            }
            2404 => {
                let transport_layer = TransportLayer::Tcp(tcp_header);
                parse_iec104_layer(input, link_layer, network_layer, transport_layer, options)
            }
            9600 => {
                let transport_layer = TransportLayer::Tcp(tcp_header);
                parse_fins_tcp_req_layer(input, link_layer, network_layer, transport_layer, options)
            }
            12001 | 48400 => {
                let transport_layer = TransportLayer::Tcp(tcp_header);
                parse_opcua_layer(input, link_layer, network_layer, transport_layer, options)
            }
            20000 => {
                let transport_layer = TransportLayer::Tcp(tcp_header);
                parse_dnp3_layer(input, link_layer, network_layer, transport_layer, options)
            }
            47808 => {
                let transport_layer = TransportLayer::Tcp(tcp_header);
                parse_bacnet_layer(input, link_layer, network_layer, transport_layer, options)
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
