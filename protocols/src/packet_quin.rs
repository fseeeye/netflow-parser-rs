use nom::bits::bits;
use nom::bytes::complete::take;
use nom::bits::complete::take as take_bits;
use nom::sequence::tuple;
use nom::number::complete::{u8, be_u16};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::convert::TryFrom;

use crate::{Header, Layer, LayerType, ParsersMap};
use crate::errors::ParseError;
use crate::parsers::{parse_tcp_header, parse_udp_header};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct MacAddress(pub [u8; 6]);

#[derive(Debug)]
pub struct QuinPacket<'a> {
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub app_type: Option<LayerType>,
    pub app_layer: Option<Layer<'a>>,
    pub error: Option<ParseError>,
}

impl<'a> QuinPacket<'a> {
    pub fn new() -> Self {
        Self {
            src_ip: None, 
            dst_ip: None, 
            src_port: None,
            dst_port: None,
            app_type: None,
            app_layer: None,
            error: None,
        }
    }

    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }

    pub fn parse(&mut self, parsers_map: ParsersMap, input: &'a [u8]) -> &[u8] {
        let input = self.parse_eth(input);

        if let Some(app_type) = self.app_type {
            if let LayerType::Error(pe) = app_type {
                self.error = Some(pe);
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
        let (input, (protocol, src_ipv4, dst_ipv4)) = match parse_ipv4_inner(input) {
            Ok(o) => o,
            Err(_) => {
                self.error = Some(ParseError::ParsingHeader);
                return input
            }
        };

        self.src_ip = Some(IpAddr::V4(src_ipv4));
        self.dst_ip = Some(IpAddr::V4(dst_ipv4));
        
        match protocol {
            0x06 => self.parse_tcp(input),
            0x11 => self.parse_udp(input),
            _ => {
                self.error = Some(ParseError::UnknownPayload);
                input
            },
        }
    }

    fn parse_ipv6(&mut self, input: &'a [u8]) -> &'a [u8] {
        let (input, (next_header, src_ipv6, dst_ipv6)) = match parse_ipv6_inner(input) {
            Ok(o) => o,
            Err(_) => {
                self.error = Some(ParseError::ParsingHeader);
                return input
            }
        };

        self.src_ip = Some(IpAddr::V6(src_ipv6));
        self.dst_ip = Some(IpAddr::V6(dst_ipv6));

        match next_header {
            0x06 => self.parse_tcp(input),
            0x11 => self.parse_udp(input),
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

        self.src_port = Some(tcp_header.src_port);
        self.dst_port = Some(tcp_header.dst_port);
        self.app_type = tcp_header.get_payload();

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

        self.src_port = Some(udp_header.src_port);
        self.dst_port = Some(udp_header.dst_port);
        self.app_type = udp_header.get_payload();

        input
    }
}

fn address4(input: &[u8]) -> nom::IResult<&[u8], Ipv4Addr> {
    let (input, ipv4_addr) = take(4u8)(input)?;

    Ok((input, Ipv4Addr::from(<[u8; 4]>::try_from(ipv4_addr).unwrap())))
}

fn address6(input: &[u8]) -> nom::IResult<&[u8], Ipv6Addr> {
    let (input, ipv6) = take(16u8)(input)?;

    Ok((input, Ipv6Addr::from(<[u8; 16]>::try_from(ipv6).unwrap())))
}

fn parse_ipv4_inner(input: &[u8]) -> nom::IResult<&[u8], (u8, Ipv4Addr, Ipv4Addr)> {
    let (input, (_, header_length)): (&[u8], (u8, u8)) =
        bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
            take_bits(4usize),
            take_bits(4usize),
        )))(input)?;
    let input = &input[8..];
    let (input, protocol) = u8(input)?;
    let input = &input[2..];
    let (input, src_ipv4) = address4(input)?;
    let (mut input, dst_ipv4) = address4(input)?;

    if (header_length * 4) > 20 {
        input = &input[(header_length * 4 - 20) as usize..];
    }

    Ok((input, (protocol, src_ipv4, dst_ipv4)))
}

fn parse_ipv6_inner(input: &[u8]) -> nom::IResult<&[u8], (u8, Ipv6Addr, Ipv6Addr)> {
    let input = &input[6..];
    let (input, next_header) = u8(input)?;
    let input = &input[1..];
    let (input, src_ipv6) = address6(input)?;
    let (input, dst_ipv6) = address6(input)?;

    Ok((input, (next_header, src_ipv6, dst_ipv6)))
}