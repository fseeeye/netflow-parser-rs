use nom::bits::bits;
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::{tag, take};
use nom::combinator::eof;
use nom::multi::count;
use nom::number::complete::{be_u16, be_u32, u8};
use nom::IResult;

use super::payload::L2Payload;

#[derive(Debug, PartialEq)]
pub struct Ethernet<'a> {
    pub dst_mac: &'a [u8],
    pub src_mac: &'a [u8],
    pub link_type: u16,
}

pub fn parse_ethernet(input: &[u8]) -> IResult<&[u8], Ethernet> {
    let (input, dst_mac) = take(6usize)(input)?;
    let (input, src_mac) = take(6usize)(input)?;
    let (input, link_type) = be_u16(input)?;
    Ok((
        input,
        Ethernet {
            dst_mac,
            src_mac,
            link_type,
        },
    ))
}

#[derive(Debug, PartialEq)]
pub struct Packet<'a> {
    pub header: Ethernet<'a>,
    pub payload: L2Payload<'a>,
}
