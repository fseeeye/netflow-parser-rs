use nom::number::complete::{be_u16};

use crate::layer_type::LayerType;
use crate::{HeaderTrait, PayloadTrait};

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
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

use super::modbus_req::ModbusReqHeader;
use super::modbus_rsp::ModbusRspHeader;
use super::eof::EofHeader;

#[derive(Debug, PartialEq)]
pub enum UdpPayload<'a> {
    ModbusReq(ModbusReqHeader<'a>),
    ModbusRsp(ModbusRspHeader<'a>),
    Eof(EofHeader),
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

impl<'a> PayloadTrait<'a> for UdpPayload<'a> {
    type Header = UdpHeader;

    fn parse(
        _input: &'a [u8],
        _header: &Self::Header,
    ) -> nom::IResult<&'a [u8], Self> {
        unimplemented!();
    }    
}