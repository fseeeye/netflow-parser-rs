#[allow(unused)]
use nom::bits::bits;
#[allow(unused)]
use nom::bits::complete::take as take_bits;
#[allow(unused)]
use nom::bytes::complete::{tag, take};
#[allow(unused)]
use nom::combinator::{eof, map, peek};
#[allow(unused)]
use nom::error::{ErrorKind, Error};
#[allow(unused)]
use nom::multi::count;
#[allow(unused)]
use nom::number::complete::{be_u16, be_u32, u8};
#[allow(unused)]
use nom::sequence::tuple;
#[allow(unused)]
use nom::IResult;

use crate::PacketTrait;

#[derive(Debug, PartialEq)]
pub struct UdpPacket<'a> {
    pub udp_header: UdpHeader,
    pub udp_payload: UdpPayload<'a>,
}

#[derive(Debug, PartialEq)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

use super::modbus_req::ModbusReqPacket;
use super::eof::EofPacket;

#[derive(Debug, PartialEq)]
pub enum UdpPayload<'a> {
    ModbusReq(ModbusReqPacket<'a>),
    Eof(EofPacket<'a>),
    Unknown(&'a [u8]),
    Error(UdpPayloadError<'a>),
}

#[derive(Debug, PartialEq)]
pub enum UdpPayloadError<'a> {
    ModbusReq(&'a [u8]),
    Eof(&'a [u8]),
    NomPeek(&'a [u8]),
}

impl<'a> PacketTrait<'a> for UdpPacket<'a> {
    type Header = UdpHeader;
    type Payload = UdpPayload<'a>;
    type PayloadError = UdpPayloadError<'a>;

    fn parse_header(input: &'a [u8]) -> nom::IResult<&'a [u8], Self::Header> {
        let (input, src_port) = be_u16(input)?;
        let (input, dst_port) = be_u16(input)?;
        let (input, length) = be_u16(input)?;
        let (input, checksum) = be_u16(input)?;
        Ok((
            input,
            UdpHeader {
                src_port,
                dst_port,
                length,
                checksum
            }
        ))
    }

    fn parse_payload(
        input: &'a [u8], 
        _header: &Self::Header
    ) -> nom::IResult<&'a [u8], Self::Payload> {
        match input.len() {
            0 => match EofPacket::parse(input) {
                Ok((input, eof)) => Ok((input, UdpPayload::Eof(eof))),
                Err(_) => Ok((input, UdpPayload::Error(UdpPayloadError::Eof(input)))),
            },
            _ => match _header.src_port {
                0x01f6 => match ModbusReqPacket::parse(input) {
                    Ok((input, modbus_req)) => Ok((input, UdpPayload::ModbusReq(modbus_req))),
                    Err(_) => Ok((input, UdpPayload::Error(UdpPayloadError::ModbusReq(input)))),
                },
                _ => Ok((input, UdpPayload::Unknown(input))),
            },
        }
    }

    fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, udp_header) = Self::parse_header(input)?;
        let (input, udp_payload) = Self::parse_payload(input, &udp_header)?;
        Ok((input, Self { udp_header, udp_payload }))
    }            
}