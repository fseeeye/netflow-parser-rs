use nom::bits::bits;
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::{tag, take};
use nom::combinator::eof;
use nom::multi::count;
use nom::number::complete::{be_u16, be_u32, u8};
use nom::IResult;

use super::payload::L4Payload;

#[derive(Debug, PartialEq)]
pub struct Udp {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

pub fn parse_udp(input: &[u8]) -> IResult<&[u8], Udp> {
    let (input, src_port) = be_u16(input)?;
    let (input, dst_port) = be_u16(input)?;
    let (input, length) = be_u16(input)?;
    let (input, checksum) = be_u16(input)?;
    Ok((
        input,
        Udp {
            src_port,
            dst_port,
            length,
            checksum,
        },
    ))
}

#[derive(Debug, PartialEq)]
pub struct Packet<'a> {
    pub header: Udp,
    pub payload: L4Payload<'a>,
}
