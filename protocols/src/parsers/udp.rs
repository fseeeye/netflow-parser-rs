use nom::bits::bits;
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::{tag, take};
use nom::combinator::eof;
use nom::multi::count;
use nom::number::complete::{be_u16, be_u32, u8};
use nom::sequence::tuple;
use nom::IResult;

use crate::traits::PacketTrait; // changed
use super::parser_context::ParserContext; // added

#[derive(Debug, PartialEq)]
pub struct Udp {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

use crate::parsers::modbus; // changed

#[derive(Debug, PartialEq)]
pub enum UdpPayloadError {
    Modbus,
}

#[derive(Debug, PartialEq)]
pub enum UdpPayload<'a> {
    Modbus(modbus::ModbusPacket<'a>),
    Unknown(&'a [u8]),
    Error(UdpPayloadError),
}

#[derive(Debug, PartialEq)]
pub struct UdpPacket<'a> {
    pub header: Udp,
    pub payload: UdpPayload<'a>,
}

impl<'a> PacketTrait<'a> for UdpPacket<'a> {
    type Header = Udp;
    type Payload = UdpPayload<'a>;
	type PayloadError = UdpPayloadError;
	
	fn parse_header(input: &'a [u8], _context: &mut ParserContext) -> IResult<&'a [u8], Self::Header> {
        let (input, src_port) = be_u16(input)?;
        let (input, dst_port) = be_u16(input)?;
        let (input, length) = be_u16(input)?;
        let (input, checksum) = be_u16(input)?;
        Ok((
            input,
            Self::Header {
                src_port,
                dst_port,
                length,
                checksum,
            },
        ))
    }
	fn parse_payload(input: &'a [u8], _header: &Self::Header, context: &mut ParserContext) -> IResult<&'a [u8], Self::Payload> {
        unimplemented!();
    }
	fn parse(input: &'a [u8], context: &mut ParserContext) -> nom::IResult<&'a [u8], Self> {
        unimplemented!();
    }
}