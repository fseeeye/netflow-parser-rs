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
pub struct Tcp<'a> {
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
    pub options: Option<&'a [u8]>,
}

use crate::parsers::modbus; // changed

#[derive(Debug, PartialEq)]
pub enum TcpPayloadError {
    Modbus,
}

#[derive(Debug, PartialEq)]
pub enum TcpPayload<'a> {
    Modbus(modbus::ModbusPacket<'a>),
    Unknown(&'a [u8]),
    Error(TcpPayloadError),
}

#[derive(Debug, PartialEq)]
pub struct TcpPacket<'a> {
    header: Tcp<'a>,
    payload: TcpPayload<'a>,
}

impl<'a> PacketTrait<'a> for TcpPacket<'a> {
    type Header = Tcp<'a>;
    type Payload = TcpPayload<'a>;
	type PayloadError = TcpPayloadError;
	
	fn parse_header(input: &'a [u8], _context: &mut ParserContext) -> IResult<&'a [u8], Self::Header> {
        let (input, src_port) = be_u16(input)?;
        let (input, dst_port) = be_u16(input)?;
        let (input, seq) = be_u32(input)?;
        let (input, ack) = be_u32(input)?;
        let (input, (header_length, reserved, flags)) =
            bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
                take_bits(4usize),
                take_bits(3usize),
                take_bits(9usize),
            )))(input)?;
        let (input, window_size) = be_u16(input)?;
        let (input, checksum) = be_u16(input)?;
        let (input, urgent_pointer) = be_u16(input)?;
        let (input, options) = if (header_length * 4) > 20 {
            let (input, options) = take(header_length * 4 - 20)(input)?;
            Ok((input, Some(options)))
        } else {
            Ok((input, None))
        }?;

        _context.src_port = Some(src_port); // added
        _context.dst_port = Some(dst_port); // added

        Ok((
            input,
            Self::Header {
                src_port,
                dst_port,
                seq,
                ack,
                header_length,
                reserved,
                flags,
                window_size,
                checksum,
                urgent_pointer,
                options,
            },
        ))
    }

	fn parse_payload(input: &'a [u8], _header: &Self::Header, context: &mut ParserContext) -> IResult<&'a [u8], Self::Payload> {
        use super::modbus::ModbusPacket;
        if _header.src_port == 502 || _header.dst_port == 502 { // warning: used _header
            return match ModbusPacket::parse(input, context) {
                Ok((input, modbus)) => Ok((input, Self::Payload::Modbus(modbus))),
                Err(_) => Ok((input, Self::Payload::Error(Self::PayloadError::Modbus))),
            };
        }
        Ok((input, Self::Payload::Unknown(input)))
    }
    
	fn parse(input: &'a [u8], context: &mut ParserContext) -> nom::IResult<&'a [u8], Self> {
        let (input, header) = Self::parse_header(input, context)?;
        let (input, payload) = Self::parse_payload(input, &header, context)?;
        Ok((input, Self { header, payload }))
    }
}