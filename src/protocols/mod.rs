pub mod ethernet;
pub mod ipv4;
pub mod ipv6;
pub mod modbus;
pub mod tcp;
pub mod udp;

use nom::combinator::peek;
use nom::number::complete::u8;
use nom::IResult;

use ethernet::{parse_ethernet, Ethernet};
use ipv4::{parse_ipv4, Ipv4};
use ipv6::{parse_ipv6, Ipv6};

use modbus::{parse_modbus_packet, ModbusPacket};
use tcp::{parse_tcp, Tcp};
use udp::{parse_udp, Udp};

#[derive(Debug, PartialEq)]
pub enum L2<'a> {
    Ethernet(Ethernet<'a>),
}

#[derive(Debug, PartialEq)]
pub enum L3<'a> {
    Ipv4(Ipv4<'a>),
    Ipv6(Ipv6<'a>),
}

#[derive(Debug, PartialEq)]
pub enum L4<'a> {
    Tcp(Tcp<'a>),
    Udp(Udp),
}

#[derive(Debug, PartialEq)]
pub enum App<'a> {
    Modbus(ModbusPacket<'a>),
}

#[derive(Debug, PartialEq)]
pub struct Packet<'a> {
    pub l2: Ethernet<'a>,
    pub l3: L3<'a>,
    pub l4: L4<'a>,
    pub app: App<'a>,
}

fn parse_l3(input: &[u8]) -> IResult<&[u8], L3> {
    let (input, version) = peek(u8)(input)?;
    let (input, l3) = match version >> 4 {
        0x04 => {
            let (input, ipv4) = parse_ipv4(input)?;
            Ok((input, L3::Ipv4(ipv4)))
        }
        0x06 => {
            let (input, ipv6) = parse_ipv6(input)?;
            Ok((input, L3::Ipv6(ipv6)))
        }
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, l3))
}

fn parse_l4(input: &[u8], proto: u8) -> IResult<&[u8], L4> {
    match proto {
        0x06 => {
            let (input, tcp) = parse_tcp(input)?;
            Ok((input, L4::Tcp(tcp)))
        }
        0x11 => {
            let (input, udp) = parse_udp(input)?;
            Ok((input, L4::Udp(udp)))
        }
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }
}

fn parse_udp_based_app<'a>(input: &'a [u8], udp: &Udp) -> IResult<&'a [u8], App<'a>> {
    Err(nom::Err::Error(nom::error::Error::new(
        input,
        nom::error::ErrorKind::Verify,
    )))
}

fn parse_tcp_based_app<'a>(input: &'a [u8], tcp: &Tcp) -> IResult<&'a [u8], App<'a>> {
    if tcp.header.src_port == 502 || tcp.header.dst_port == 502 {
        let (input, modbus) = parse_modbus_packet(input)?;
        return Ok((input, App::Modbus(modbus)));
    }
    Err(nom::Err::Error(nom::error::Error::new(
        input,
        nom::error::ErrorKind::Verify,
    )))
}

fn parse_app<'a>(input: &'a [u8], l4: &L4) -> IResult<&'a [u8], App<'a>> {
    match l4 {
        L4::Udp(udp) => parse_udp_based_app(input, udp),
        L4::Tcp(tcp) => parse_tcp_based_app(input, tcp),
    }
}

pub fn parse_packet(input: &[u8]) -> IResult<&[u8], Packet> {
    let (input, l2) = parse_ethernet(input)?;
    let (input, l3) = parse_l3(input)?;
    let (input, l4) = match &l3 {
        L3::Ipv4(ipv4) => parse_l4(input, ipv4.header.protocol),
        L3::Ipv6(ipv6) => parse_l4(input, ipv6.prefix.next_header),
    }?;
    let (input, app) = parse_app(input, &l4)?;
    Ok((input, Packet { l2, l3, l4, app }))
}
