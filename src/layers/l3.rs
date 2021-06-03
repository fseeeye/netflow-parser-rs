use crate::error::Error;
use crate::protocols::{ipv4, ipv6};
use nom::combinator::peek;
use nom::number::complete::u8;

#[derive(Debug, PartialEq)]
pub enum L3<'a> {
    Ipv4(ipv4::Ipv4<'a>),
    Ipv6(ipv6::Ipv6<'a>),
    Unknown,
    Error(Error),
}

pub fn parse_l3(input: &[u8]) -> (&[u8], L3) {
    let peeked_version = peek::<_, _, (), _>(u8)(input);
    match peeked_version {
        Ok((input, version)) => match version >> 4 {
            0x04 => match ipv4::parse_ipv4(input) {
                Ok((input, ipv4_packet)) => (input, L3::Ipv4(ipv4_packet)),
                Err(_) => (input, L3::Error(Error::Ipv4)),
            },
            0x06 => match ipv6::parse_ipv6(input) {
                Ok((input, ipv6_packet)) => (input, L3::Ipv6(ipv6_packet)),
                Err(_) => (input, L3::Error(Error::Ipv6)),
            },
            _ => (input, L3::Unknown),
        },
        Err(_) => (input, L3::Unknown),
    }
}
