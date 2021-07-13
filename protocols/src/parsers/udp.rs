use nom::number::complete::{be_u16};

use crate::PacketTrait;

#[derive(Debug, PartialEq)]
pub struct UdpPacket<'a> {
    pub header: UdpHeader,
    pub payload: UdpPayload<'a>,
}

#[derive(Debug, PartialEq)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

use super::modbus_req;
use super::modbus_rsp;

#[derive(Debug, PartialEq)]
pub enum UdpPayload<'a> {
    ModbusReq(modbus_req::ModbusReqPacket<'a>),
    ModbusRsp(modbus_rsp::ModbusRspPacket<'a>),
    Unknown(&'a [u8]),
    Error(UdpPayloadError<'a>),
}

#[derive(Debug, PartialEq)]
pub enum UdpPayloadError<'a> {
    ModbusReq(&'a [u8]),
    ModbusRsp(&'a [u8]),
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
                checksum,
            },
        ))
    }

    fn parse_payload(
        _input: &'a [u8],
        _header: &Self::Header,
    ) -> nom::IResult<&'a [u8], Self::Payload> {
        unimplemented!();
    }

    fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, header) = Self::parse_header(input)?;
        let (input, payload) = Self::parse_payload(input, &header)?;
        Ok((input, Self { header, payload }))
    }
}
