pub use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nom::bytes::complete::take;
use nom::number::complete::{be_u16, u8};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::ops::BitAnd;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize)]
pub struct MacAddress(pub [u8; 6]);

#[inline(always)]
#[allow(dead_code)]
pub fn mac_address(input: &[u8]) -> nom::IResult<&[u8], MacAddress> {
    let (input, mac) = take(6usize)(input)?;

    match <[u8; 6]>::try_from(mac) {
        Ok(address) => Ok((input, MacAddress(address))),
        Err(_e) => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Switch,
        ))),
    }
}

#[inline(always)]
#[allow(dead_code)]
pub fn address4(input: &[u8]) -> nom::IResult<&[u8], Ipv4Addr> {
    let (input, ipv4_addr) = take(4u8)(input)?;

    match <[u8; 4]>::try_from(ipv4_addr) {
        Ok(address) => Ok((input, Ipv4Addr::from(address))),
        Err(_e) => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Switch,
        ))),
    }
}

#[inline(always)]
#[allow(dead_code)]
pub fn address6(input: &[u8]) -> nom::IResult<&[u8], Ipv6Addr> {
    let (input, ipv6_addr) = take(16u8)(input)?;

    match <[u8; 16]>::try_from(ipv6_addr) {
        Ok(address) => Ok((input, Ipv6Addr::from(address))),
        Err(_e) => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Switch,
        ))),
    }
}

#[inline(always)]
#[allow(dead_code)]
pub fn slice_u4_4(input: &[u8]) -> nom::IResult<&[u8], [u8; 4]> {
    let (input, (num1, num2, num3, num4)) =
        nom::bits::bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(nom::sequence::tuple((
            nom::bits::complete::take(4usize),
            nom::bits::complete::take(4usize),
            nom::bits::complete::take(4usize),
            nom::bits::complete::take(4usize),
        )))(input)?;
    Ok((input, [num1, num2, num3, num4]))
}

#[inline(always)]
#[allow(dead_code)]
pub fn slice_u4_6(input: &[u8]) -> nom::IResult<&[u8], [u8; 6]> {
    let (input, (num1, num2, num3, num4, num5, num6)) =
        nom::bits::bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(nom::sequence::tuple((
            nom::bits::complete::take(4usize),
            nom::bits::complete::take(4usize),
            nom::bits::complete::take(4usize),
            nom::bits::complete::take(4usize),
            nom::bits::complete::take(4usize),
            nom::bits::complete::take(4usize),
        )))(input)?;
    Ok((input, [num1, num2, num3, num4, num5, num6]))
}

#[inline(always)]
#[allow(dead_code)]
pub fn slice_u8_2(input: &[u8]) -> nom::IResult<&[u8], [u8; 2]> {
    let (input, num1) = u8(input)?;
    let (input, num2) = u8(input)?;

    Ok((input, [num1, num2]))
}

#[inline(always)]
#[allow(dead_code)]
pub fn slice_u8_3(input: &[u8]) -> nom::IResult<&[u8], [u8; 3]> {
    let (input, num1) = u8(input)?;
    let (input, num2) = u8(input)?;
    let (input, num3) = u8(input)?;

    Ok((input, [num1, num2, num3]))
}

#[inline(always)]
#[allow(dead_code)]
pub fn slice_u8_4(input: &[u8]) -> nom::IResult<&[u8], [u8; 4]> {
    let (input, num1) = u8(input)?;
    let (input, num2) = u8(input)?;
    let (input, num3) = u8(input)?;
    let (input, num4) = u8(input)?;
    Ok((input, [num1, num2, num3, num4]))
}

#[inline(always)]
#[allow(dead_code)]
pub fn slice_u8_5(input: &[u8]) -> nom::IResult<&[u8], [u8; 5]> {
    let (input, num1) = u8(input)?;
    let (input, num2) = u8(input)?;
    let (input, num3) = u8(input)?;
    let (input, num4) = u8(input)?;
    let (input, num5) = u8(input)?;
    Ok((input, [num1, num2, num3, num4, num5]))
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct BerTL {
    pub tag: u8,
    pub length: u16,
}

#[inline(always)]
#[allow(dead_code)]
pub fn ber_tl(input: &[u8]) -> nom::IResult<&[u8], BerTL> {
    let (input, tag) = u8(input)?;
    if tag.bitand(0x1f) > 0x1e {
        panic!("Tag is not Supported!")
    }
    let (input, length) = u8(input)?;
    if length < 128 {
        //短形式
        Ok((
            input,
            BerTL {
                tag,
                length: length as u16,
            },
        ))
    } else {
        //长形式
        if length == 128 {
            //不定长
            let mut length: u16 = 0;
            let mut input = input;
            let mut tmp;
            (input, tmp) = be_u16(input)?;
            loop {
                if tmp == 0 {
                    return Ok((input, BerTL { tag, length }));
                } else {
                    length += tmp;
                    (input, tmp) = be_u16(input)?;
                }
            }
        } else {
            let (input, slice) = take((length - 128) as usize)(input)?;
            let mut length: u8 = 0;
            for i in slice {
                length += *i
            }
            Ok((
                input,
                BerTL {
                    tag,
                    length: length as u16,
                },
            ))
        }
    }
}
