pub use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nom::bytes::complete::take;
use nom::number::complete::{be_u16, u8};
use serde::{Deserialize, Serialize};
use tracing::trace;

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

impl std::fmt::Display for BerTL {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TL(tag: 0x{:x}, len: {})", self.tag, self.length)
    }
}

#[inline]
pub fn ber_tl(input_raw: &[u8]) -> nom::IResult<&[u8], BerTL> {
    let (input, tag) = u8(input_raw)?;
    if tag.bitand(0x1f) > 0x1e {
        return Err(nom::Err::Error(nom::error::Error {
            input: input_raw,
            code: nom::error::ErrorKind::Tag,
        }));
    }
    let (input, length) = u8(input)?;
    if length < 128 {
        //短形式
        trace!(target: "PARSER(ber_tl)", "tag: 0x{:x}, len: {}", tag, length);
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
                    trace!(target: "PARSER(ber_tl)", "tag: 0x{:x}, len: {}", tag, length);
                    return Ok((input, BerTL { tag, length }));
                } else {
                    length += tmp;
                    (input, tmp) = be_u16(input)?;
                }
            }
        } else {
            // 定长
            let (input, slice) = take((length - 128) as usize)(input)?;
            let mut length: u8 = 0;
            for i in slice {
                length += *i
            }
            trace!(target: "PARSER(ber_tl)", "tag: 0x{:x}, len: {}", tag, length);
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

#[inline(always)]
pub fn ber_tl_v(input_raw: &[u8]) -> nom::IResult<&[u8], &[u8]> {
    trace!(target: "PARSER(ber_tl_v)", "");
    let (input, _ber_tl) = ber_tl(input_raw)?;
    return Ok(take(_ber_tl.length as usize)(input)?);
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn mac_parser() {
        assert_eq!(
            mac_address(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xcc]),
            Ok((
                &[0xcc][..],
                MacAddress([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
            ))
        )
    }

    #[test]
    fn ip_address_parser() {
        assert_eq!(
            address4([192, 168, 0, 1, 0xcc].as_slice()),
            Ok((&[0xcc][..], Ipv4Addr::from_str("192.168.0.1").unwrap()))
        );

        assert_eq!(
            address6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xcc].as_slice()),
            Ok((&[0xcc][..], Ipv6Addr::from_str("::1").unwrap()))
        )
    }

    #[test]
    fn slice_parser() {
        assert_eq!(
            slice_u4_4([0x11, 0x22, 0xcc].as_slice()),
            Ok(([0xcc].as_slice(), [0x01, 0x01, 0x02, 0x02]))
        );

        assert_eq!(
            slice_u4_6([0x11, 0x22, 0x33, 0xcc].as_slice()),
            Ok(([0xcc].as_slice(), [0x01, 0x01, 0x02, 0x02, 0x03, 0x03]))
        );

        assert_eq!(
            slice_u8_2([0x01, 0x02, 0xcc].as_slice()),
            Ok(([0xcc].as_slice(), [0x01, 0x02]))
        );

        assert_eq!(
            slice_u8_3([0x01, 0x02, 0x03, 0xcc].as_slice()),
            Ok(([0xcc].as_slice(), [0x01, 0x02, 0x03]))
        );

        assert_eq!(
            slice_u8_4([0x01, 0x02, 0x03, 0x04, 0xcc].as_slice()),
            Ok(([0xcc].as_slice(), [0x01, 0x02, 0x03, 0x04]))
        );

        assert_eq!(
            slice_u8_5([0x01, 0x02, 0x03, 0x04, 0x05, 0xcc].as_slice()),
            Ok(([0xcc].as_slice(), [0x01, 0x02, 0x03, 0x04, 0x05]))
        );
    }

    #[test]
    fn tl_parser() {
        let tl_short: &[u8] = &[0x10, 0x7f, 0x00, 0xcc, 0xcc];
        assert_eq!(
            ber_tl(tl_short),
            Ok((
                [0x00, 0xcc, 0xcc].as_slice(),
                BerTL {
                    tag: 16,
                    length: 127
                }
            ))
        );

        let tl_long_unknown: &[u8] = &[0x10, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0xcc, 0xcc];
        assert_eq!(
            ber_tl(tl_long_unknown),
            Ok(([0xcc, 0xcc].as_slice(), BerTL { tag: 16, length: 3 }))
        );

        let tl_long_known: &[u8] = &[0x10, 0x82, 0x01, 0x02, 0xcc, 0xcc];
        assert_eq!(
            ber_tl(tl_long_known),
            Ok(([0xcc, 0xcc].as_slice(), BerTL { tag: 16, length: 3 }))
        );

        let tl_error_tag: &[u8] = &[0x1f, 0xcc];
        assert_eq!(
            ber_tl(tl_error_tag),
            Err(nom::Err::Error(nom::error::Error {
                input: [0x1f, 0xcc].as_slice(),
                code: nom::error::ErrorKind::Tag
            }))
        );
    }
}
