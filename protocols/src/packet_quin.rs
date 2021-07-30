use nom::number::complete::be_u16;

use std::net::IpAddr;

use crate::layer::{NetworkLayer, TransportLayer};
use crate::{Header, Layer, LayerType, ParsersMap};
use crate::errors::ParseError;
use crate::parsers::{parse_ipv4_header, parse_ipv6_header, parse_tcp_header, parse_udp_header};

#[derive(Debug, PartialEq, Eq)]
pub struct QuinPacketOptions {
    stop: bool,
}

impl QuinPacketOptions {
    pub fn new(stop: bool) -> Self {
        Self {
            stop
        }
    }
}

#[derive(Debug)]
pub struct QuinPacket<'a> {
    pub net_layer: Option<NetworkLayer<'a>>,
    pub trans_layer: Option<TransportLayer<'a>>,
    pub app_type: Option<LayerType>,
    pub app_layer: Option<Layer<'a>>,
    pub error: Option<ParseError>,
    pub options: QuinPacketOptions,
}

impl<'a> QuinPacket<'a> {
    pub fn new(options: QuinPacketOptions) -> Self {
        Self {
            net_layer: None,
            trans_layer: None,
            app_type: None,
            app_layer: None,
            error: None,
            options,
        }
    }

    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }

    pub fn get_ips(&self) -> Option<(IpAddr, IpAddr)> {
        if let Some(net_layer) = &self.net_layer {
            match net_layer {
                NetworkLayer::Ipv4(ipv4) => Some((IpAddr::V4(ipv4.src_ip), IpAddr::V4(ipv4.dst_ip))),
                NetworkLayer::Ipv6(ipv6) => Some((IpAddr::V6(ipv6.src_ip), IpAddr::V6(ipv6.dst_ip))),
            }
        } else {
            None
        }
    }

    pub fn get_ports(&self) -> Option<(u16, u16)> {
        if let Some(trans_layer) = &self.trans_layer {
            match trans_layer {
                TransportLayer::Tcp(tcp) => Some((tcp.src_port, tcp.dst_port)),
                TransportLayer::Udp(udp) => Some((udp.src_port, udp.dst_port)),
            }
        } else {
            None
        }
    }

    pub fn parse(&mut self, parsers_map: ParsersMap, input: &'a [u8]) -> &[u8] {
        let input = self.parse_eth(input);

        if let Some(app_type) = self.app_type {
            // Error occurred: app_type is LayerType::Error
            if let LayerType::Error(pe) = app_type {
                self.error = Some(pe);
                return input
            }

            // return when `options.stop` is set to true
            if self.options.stop == true {
                return input
            }

            if let Some(parser) = parsers_map.get(&app_type) {
                match parser(input) {
                    Ok((input, (nlayer, _next))) => {
                        self.app_layer = Some(nlayer);
                        return input
                    },
                    Err(_) => { // Error occurred: parsing application layer. update self.error to ParseError::ParsingHeader
                        self.error = Some(ParseError::ParsingHeader);
                    },
                };
            } else { // Error occurred: Can't find parser correspond to self.next
                self.error = Some(ParseError::UnregisteredParser);
            }
        }

        if input.len() > 0 {
            self.error = Some(ParseError::NotEndPayload);
        }

        input
    }

    fn parse_eth(&mut self, input: &'a [u8]) -> &'a [u8] {
        let input = &input[12..]; // consume src_mac & dst_mac
        let (input, link_type): (&[u8], u16) = match be_u16::<_, (_, _)>(input) {
            Ok(o) => o,
            Err(_) => {
                self.error = Some(ParseError::ParsingHeader);
                return input
            }
        };

        match link_type {
            0x0800 => {
                self.parse_ipv4(input)
            },
            0x86DD => {
                self.parse_ipv6(input)
            },
            _ => input
        }
    }

    fn parse_ipv4(&mut self, input: &'a [u8]) -> &'a [u8] {
        let (input, ipv4_header) = match parse_ipv4_header(input) {
            Ok(o) => o,
            Err(_) => {
                self.error = Some(ParseError::ParsingHeader);
                return input
            }
        };
        
        match ipv4_header.protocol {
            0x06 => {
                self.net_layer = Some(NetworkLayer::Ipv4(ipv4_header));
                self.parse_tcp(input)
            },
            0x11 => {
                self.net_layer = Some(NetworkLayer::Ipv4(ipv4_header));
                self.parse_udp(input)
            },
            _ => {
                self.error = Some(ParseError::UnknownPayload);
                input
            },
        }
    }

    fn parse_ipv6(&mut self, input: &'a [u8]) -> &'a [u8] {
        let (input, ipv6_header) = match parse_ipv6_header(input) {
            Ok(o) => o,
            Err(_) => {
                self.error = Some(ParseError::ParsingHeader);
                return input
            }
        };

        match ipv6_header.next_header {
            0x06 => {
                self.net_layer = Some(NetworkLayer::Ipv6(ipv6_header));
                self.parse_tcp(input)
            },
            0x11 => {
                self.net_layer = Some(NetworkLayer::Ipv6(ipv6_header));
                self.parse_udp(input)
            },
            _ => {
                self.error = Some(ParseError::UnknownPayload);
                input
            },
        }
    }

    fn parse_tcp(&mut self, input: &'a [u8]) -> &'a [u8] {
        let (input, tcp_header) = match parse_tcp_header(input) {
            Ok(o) => o,
            Err(_e) => {
                self.error = Some(ParseError::ParsingHeader);
                return input
            }
        };

        self.app_type = tcp_header.get_payload();
        self.trans_layer = Some(TransportLayer::Tcp(tcp_header));

        input
    }

    fn parse_udp(&mut self, input: &'a [u8]) -> &'a [u8] {
        let (input, udp_header) = match parse_udp_header(input) {
            Ok(o) => o,
            Err(_e) => {
                self.error = Some(ParseError::ParsingHeader);
                return input
            }
        };

        self.app_type = udp_header.get_payload();
        self.trans_layer = Some(TransportLayer::Udp(udp_header));

        input
    }
}