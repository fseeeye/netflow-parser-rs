use nom::bits::bits;
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::{tag, take};
use nom::multi::count;
use nom::combinator::eof;
use nom::number::complete::{be_u32, be_u16, u8};
use nom::IResult;

#[derive(Debug, PartialEq)]
pub struct TcpHeader {
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
}

#[derive(Debug, PartialEq)]
pub struct Tcp<'a> {
    pub header: TcpHeader,
    pub options: Option<&'a [u8]>,
}

fn parse_bits_tcp_header(input: (&[u8], usize)) -> IResult<(&[u8], usize),  TcpHeader> {
    let (input, src_port) = take_bits(16usize)(input)?;
    let (input, dst_port) = take_bits(16usize)(input)?;
    let (input, seq) = take_bits(32usize)(input)?;
    let (input, ack) = take_bits(32usize)(input)?;
    let (input, header_length) = take_bits(4usize)(input)?;
    let (input, reserved) = take_bits(3usize)(input)?;
    let (input, flags) = take_bits(9usize)(input)?;
    let (input, window_size) = take_bits(16usize)(input)?;
    let (input, checksum) = take_bits(16usize)(input)?;
    let (input, urgent_pointer) = take_bits(16usize)(input)?;
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
            urgent_pointer
        }
    ))
}

fn parse_tcp_header(input: &[u8]) -> IResult<&[u8], TcpHeader> {
    bits(parse_bits_tcp_header)(input)
}

pub fn parse_tcp(input: &[u8]) -> IResult<&[u8], Tcp> {
    let (input, header) = parse_tcp_header(input)?;
    let (input, options) = if (header.header_length * 4) > 20 {
        let (input, options) = take(header.header_length * 4 - 20)(input)?;
        Ok((input, Some(options)))
    } else {
        Ok((input, None))
    }?;
    Ok((
        input,
        Tcp {
            header,
            options
        }
    ))
}