use nom::bits::bits;
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::{tag, take};
use nom::combinator::eof;
use nom::multi::count;
use nom::number::complete::{be_u16, be_u32, u8};
use nom::sequence::tuple;
use nom::IResult;

use crate::PacketTrait;

#[derive(Debug, PartialEq)]
pub struct TcpPacket<'a> {
    header: TcpHeader<'a>,
    payload: TcpPayload<'a>,
}
#[derive(Debug, PartialEq)]
pub struct TcpHeader<'a> {
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

use super::eof::EofPacket;
use super::modbus_req::ModbusReqPacket;
use super::modbus_rsp::ModbusRspPacket;

#[derive(Debug, PartialEq)]
pub enum TcpPayload<'a> {
    ModbusReq(ModbusReqPacket<'a>),
    ModbusRsp(ModbusRspPacket<'a>),
    Eof(EofPacket<'a>),
    Unknown(&'a [u8]),
    Error(TcpPayloadError),
}

#[derive(Debug, PartialEq)]
pub enum TcpPayloadError {
    ModbusReq,
    ModbusRsp,
    Eof,
}

impl<'a> PacketTrait<'a> for TcpPacket<'a> {
    type Header = TcpHeader<'a>;
    type Payload = TcpPayload<'a>;
    type PayloadError = TcpPayloadError;

    fn parse_header(input: &'a [u8]) -> nom::IResult<&'a [u8], Self::Header> {
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
                urgent_pointer,
                options,
            },
        ))
    }

    fn parse_payload(
        input: &'a [u8],
        _header: &Self::Header,
    ) -> nom::IResult<&'a [u8], Self::Payload> {
        match input.len() {
            0 => match EofPacket::parse(input) {
                Ok((input, eof)) => Ok((input, TcpPayload::Eof(eof))),
                Err(_) => Ok((input, TcpPayload::Error(TcpPayloadError::Eof))),
            },
            _ => match _header.src_port {
                502 => match ModbusRspPacket::parse(input) {
                    Ok((input, modbus_rsp)) => Ok((input, TcpPayload::ModbusRsp(modbus_rsp))),
                    Err(_) => Ok((input, TcpPayload::Error(TcpPayloadError::ModbusRsp))),
                },
                _ => match _header.dst_port {
                    502 => match ModbusReqPacket::parse(input) {
                        Ok((input, modbus_req)) => Ok((input, TcpPayload::ModbusReq(modbus_req))),
                        Err(_) => Ok((input, TcpPayload::Error(TcpPayloadError::ModbusReq))),
                    },
                    _ => Ok((input, TcpPayload::Unknown(input))),
                },
            },
        }
    }

    fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, header) = Self::parse_header(input)?;
        let (input, payload) = Self::parse_payload(input, &header)?;
        Ok((input, Self { header, payload }))
    }
}
