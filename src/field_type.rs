use nom::bytes::complete::take;
use std::{convert::TryFrom};
pub use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct MacAddress(pub [u8; 6]);

pub fn mac_address(input: &[u8]) -> nom::IResult<&[u8], MacAddress> {
    let (input, mac) = take(6usize)(input)?;

    match <[u8; 6]>::try_from(mac) {
        Ok(address) => Ok((input, MacAddress(address))),
        Err(_e) => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Switch
        )))
    }
}

pub fn address4(input: &[u8]) -> nom::IResult<&[u8], Ipv4Addr> {
    let (input, ipv4_addr) = take(4u8)(input)?;

    match <[u8; 4]>::try_from(ipv4_addr) {
        Ok(address) => Ok((
            input,
            Ipv4Addr::from(address),
        )),
        Err(_e) => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Switch
        )))
    }
}

pub fn address6(input: &[u8]) -> nom::IResult<&[u8], Ipv6Addr> {
    let (input, ipv6_addr) = take(16u8)(input)?;

    match <[u8; 16]>::try_from(ipv6_addr) {
        Ok(address) => Ok((
            input,
            Ipv6Addr::from(address),
        )),
        Err(_e) => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Switch
        )))
    }
}