use nom::number::complete::{be_u16};

use crate::types::LayerType;
use crate::{PacketTrait, HeaderTrait, PayloadTrait};

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
    fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, header) = UdpHeader::parse(input)?;
        let (input, payload) = UdpPayload::parse(input, &header)?;
        Ok((input, Self { header, payload }))
    }
}

impl<'a> HeaderTrait<'a> for UdpHeader {
    fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
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

    fn get_type(&self) -> LayerType {
        return LayerType::Udp;
    }
}

impl<'a> PayloadTrait<'a> for UdpPayload<'a> {
    type Header = UdpHeader;

    fn parse(
        _input: &'a [u8],
        _header: &Self::Header,
    ) -> nom::IResult<&'a [u8], Self> {
        unimplemented!();
    }    
}