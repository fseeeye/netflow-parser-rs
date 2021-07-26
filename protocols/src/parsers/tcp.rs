use nom::bits::bits;
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::take;
use nom::number::complete::{be_u16, be_u32};
use nom::sequence::tuple;

use crate::layer_type::LayerType;
use crate::{HeaderTrait, PayloadTrait};

// TCP Header Format
//
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |          Source Port          |       Destination Port        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                        Sequence Number                        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Acknowledgment Number                      |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  Data |           |U|A|P|R|S|F|                               |
//   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
//   |       |           |G|K|H|T|N|N|                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |           Checksum            |         Urgent Pointer        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Options                    |    Padding    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                             data                              |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// TCP Flags:
//    URG:  Urgent Pointer field significant
//    ACK:  Acknowledgment field significant
//    PSH:  Push Function
//    RST:  Reset the connection
//    SYN:  Synchronize sequence numbers
//    FIN:  No more data from sender

#[derive(Debug, PartialEq, Clone, Copy)]
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

impl<'a> HeaderTrait<'a> for TcpHeader<'a> {
    fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
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

    fn get_type(&self) -> LayerType {
        return LayerType::Tcp
    }
}

use super::eof::EofHeader;
use super::modbus_req::ModbusReqHeader;
use super::modbus_rsp::ModbusRspHeader;

#[derive(Debug, PartialEq)]
pub enum TcpPayload<'a> {
    ModbusReq(ModbusReqHeader<'a>),
    ModbusRsp(ModbusRspHeader<'a>),
    Eof(EofHeader),
    Unknown(&'a [u8]),
    Error(TcpPayloadError<'a>),
}

#[derive(Debug, PartialEq)]
pub enum TcpPayloadError<'a> {
    ModbusReq(&'a [u8]),
    ModbusRsp(&'a [u8]),
    Eof(&'a [u8]),
    NomPeek(&'a [u8]),
}

impl<'a> PayloadTrait<'a> for TcpPayload<'a> {
    type Header = TcpHeader<'a>;

    fn parse(
        input: &'a [u8],
        _header: &Self::Header,
    ) -> nom::IResult<&'a [u8], Self> {
        match input.len() {
            0 => match EofHeader::parse(input) {
                Ok((input, eof)) => Ok((input, TcpPayload::Eof(eof))),
                Err(_) => Ok((input, TcpPayload::Error(TcpPayloadError::Eof(input)))),
            },
            _ => match _header.src_port {
                502 => match ModbusRspHeader::parse(input) {
                    Ok((input, modbus_rsp)) => Ok((input, TcpPayload::ModbusRsp(modbus_rsp))),
                    Err(_) => Ok((input, TcpPayload::Error(TcpPayloadError::ModbusRsp(input)))),
                },
                _ => match _header.dst_port {
                    502 => match ModbusReqHeader::parse(input) {
                        Ok((input, modbus_req)) => Ok((input, TcpPayload::ModbusReq(modbus_req))),
                        Err(_) => Ok((input, TcpPayload::Error(TcpPayloadError::ModbusReq(input)))),
                    },
                    _ => Ok((input, TcpPayload::Unknown(input))),
                },
            },
        }
    }
}