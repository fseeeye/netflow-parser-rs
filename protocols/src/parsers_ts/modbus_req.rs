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
pub struct ModbusReqPacket<'a> {
    pub modbus_req_header: ModbusReqHeader<'a>,
    pub modbus_req_payload: ModbusReqPayload<'a>,
}

#[derive(Debug, PartialEq)]
pub struct ModbusReqHeader<'a> {
    pub mbap_header: MbapHeader,
    pub pdu: PDU<'a>,
}

use super::eof::EofPacket;
#[derive(Debug, PartialEq)]
pub enum ModbusReqPayload<'a> {
    Eof(EofPacket<'a>),
    Unknown(&'a [u8]),
    Error(ModbusReqPayloadError<'a>),
}

#[derive(Debug, PartialEq)]
pub enum ModbusReqPayloadError<'a> {
    Eof(&'a [u8]),
    NomPeek(&'a [u8]),
}

impl<'a> PacketTrait<'a> for ModbusReqPacket<'a> {
    type Header = ModbusReqHeader<'a>;
    type Payload = ModbusReqPayload<'a>;
    type PayloadError = ModbusReqPayloadError<'a>;

    fn parse_header(input: &'a [u8]) -> nom::IResult<&'a [u8], Self::Header> {
        let (input, mbap_header) = parse_mbap_header(input)?;
        let (input, pdu) = parse_pdu(input)?;
        Ok((
            input,
            ModbusReqHeader {
                mbap_header,
                pdu
            }
        ))
    }

    fn parse_payload(
        input: &'a [u8], 
        _header: &Self::Header
    ) -> nom::IResult<&'a [u8], Self::Payload> {
        match input.len() {
            0 => match EofPacket::parse(input) {
                Ok((input, eof)) => Ok((input, ModbusReqPayload::Eof(eof))),
                Err(_) => Ok((input, ModbusReqPayload::Error(ModbusReqPayloadError::Eof(input)))),
            },
            _ => Ok((input, ModbusReqPayload::Unknown(input))),
        }
    }

    fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, modbus_req_header) = Self::parse_header(input)?;
        let (input, modbus_req_payload) = Self::parse_payload(input, &modbus_req_header)?;
        Ok((input, Self { modbus_req_header, modbus_req_payload }))
    }            
}

#[derive(Debug, PartialEq)]
pub struct MbapHeader {
    pub transaction_id: u16,
    pub protocol_id: u16,
    pub length: u16,
    pub unit_id: u8,
}

#[derive(Debug, PartialEq)]
pub struct ReadFileRecordSubRequest {
    pub ref_type: u8,
    pub file_number: u16,
    pub record_number: u16,
    pub record_length: u16,
}

#[derive(Debug, PartialEq)]
pub struct WriteFileRecordSubRequest<'a> {
    pub ref_type: u8,
    pub file_number: u16,
    pub record_number: u16,
    pub record_length: u16,
    pub record_data: &'a [u8],
}

#[derive(Debug, PartialEq)]
pub enum Data<'a> {
    ReadCoils {
         start_address: u16,
         count: u16,
    },
    ReadDiscreInputs {
         start_address: u16,
         count: u16,
    },
    ReadHoldingRegisters {
         start_address: u16,
         count: u16,
    },
    ReadInputRegisters {
         start_address: u16,
         count: u16,
    },
    WriteSingleCoil {
         output_address: u16,
         output_value: u16,
    },
    WriteSingleRegister {
         register_address: u16,
         register_value: u16,
    },
    ReadExceptionStatus {},
    GetCommEventCounter {},
    GetCommEventLog {},
    WriteMultipleCoils {
         start_address: u16,
         output_count: u16,
         byte_count: u8,
         output_values: Vec<u8>,
    },
    WriteMultipleRegisters {
         start_address: u16,
         output_count: u16,
         byte_count: u8,
         output_values: Vec<u16>,
    },
    ReportServerID {},
    ReadFileRecord {
         byte_count: u8,
         sub_requests: Vec<ReadFileRecordSubRequest>,
    },
    WriteFileRecord {
         byte_count: u8,
         sub_requests: Vec<WriteFileRecordSubRequest<'a>>,
    },
    MaskWriteRegister {
         ref_address: u16,
         and_mask: u16,
         or_mask: u16,
    },
    ReadWriteMultipleRegisters {
         read_start_address: u16,
         read_count: u16,
         write_start_address: u16,
         write_count: u16,
         write_byte_count: u8,
         write_register_values: &'a [u8],
    },
    ReadFIFOQueue {
         fifo_pointer_address: u16,
    }
}

#[derive(Debug, PartialEq)]
pub struct PDU<'a> {
    pub function_code: u8,
    pub data: Data<'a>,
}

pub fn parse_mbap_header(input: &[u8]) -> IResult<&[u8], MbapHeader> {
    let (input, transaction_id) = be_u16(input)?;
    let (input, protocol_id) = be_u16(input)?;
    let (input, length) = be_u16(input)?;
    let (input, unit_id) = u8(input)?;
    Ok((
        input,
        MbapHeader {
            transaction_id,
            protocol_id,
            length,
            unit_id
        }
    ))
}

pub fn parse_read_file_record_sub_request(input: &[u8]) -> IResult<&[u8], ReadFileRecordSubRequest> {
    let (input, ref_type) = u8(input)?;
    let (input, file_number) = be_u16(input)?;
    let (input, record_number) = be_u16(input)?;
    let (input, record_length) = be_u16(input)?;
    Ok((
        input,
        ReadFileRecordSubRequest {
            ref_type,
            file_number,
            record_number,
            record_length
        }
    ))
}

pub fn parse_write_file_record_sub_request(input: &[u8]) -> IResult<&[u8], WriteFileRecordSubRequest> {
    let (input, ref_type) = u8(input)?;
    let (input, file_number) = be_u16(input)?;
    let (input, record_number) = be_u16(input)?;
    let (input, record_length) = be_u16(input)?;
    let (input, record_data) = take(record_length as usize * 2 as usize)(input)?;
    Ok((
        input,
        WriteFileRecordSubRequest {
            ref_type,
            file_number,
            record_number,
            record_length,
            record_data
        }
    ))
}

fn parse_read_coils(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, start_address) = be_u16(input)?;
    let (input, count) = be_u16(input)?;
    Ok((
        input,
        Data::ReadCoils {
            start_address,
            count
        }
    ))
}

fn parse_read_discre_inputs(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, start_address) = be_u16(input)?;
    let (input, count) = be_u16(input)?;
    Ok((
        input,
        Data::ReadDiscreInputs {
            start_address,
            count
        }
    ))
}

fn parse_read_holding_registers(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, start_address) = be_u16(input)?;
    let (input, count) = be_u16(input)?;
    Ok((
        input,
        Data::ReadHoldingRegisters {
            start_address,
            count
        }
    ))
}

fn parse_read_input_registers(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, start_address) = be_u16(input)?;
    let (input, count) = be_u16(input)?;
    Ok((
        input,
        Data::ReadInputRegisters {
            start_address,
            count
        }
    ))
}

fn parse_write_single_coil(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, output_address) = be_u16(input)?;
    let (input, output_value) = be_u16(input)?;
    Ok((
        input,
        Data::WriteSingleCoil {
            output_address,
            output_value
        }
    ))
}

fn parse_write_single_register(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, register_address) = be_u16(input)?;
    let (input, register_value) = be_u16(input)?;
    Ok((
        input,
        Data::WriteSingleRegister {
            register_address,
            register_value
        }
    ))
}

fn parse_read_exception_status(input: &[u8]) -> IResult<&[u8], Data> {
     let (input, _) = eof(input)?;
     Ok((
         input,
         Data::ReadExceptionStatus {}
     ))
}

fn parse_get_comm_event_counter(input: &[u8]) -> IResult<&[u8], Data> {
     let (input, _) = eof(input)?;
     Ok((
         input,
         Data::GetCommEventCounter {}
     ))
}

fn parse_get_comm_event_log(input: &[u8]) -> IResult<&[u8], Data> {
     let (input, _) = eof(input)?;
     Ok((
         input,
         Data::GetCommEventLog {}
     ))
}

fn parse_write_multiple_coils(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, start_address) = be_u16(input)?;
    let (input, output_count) = be_u16(input)?;
    let (input, byte_count) = u8(input)?;
    let (input, output_values) = count(u8, byte_count as usize as usize)(input)?;
    Ok((
        input,
        Data::WriteMultipleCoils {
            start_address,
            output_count,
            byte_count,
            output_values
        }
    ))
}

fn parse_write_multiple_registers(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, start_address) = be_u16(input)?;
    let (input, output_count) = be_u16(input)?;
    let (input, byte_count) = u8(input)?;
    let (input, output_values) = count(be_u16, byte_count as usize as usize)(input)?;
    Ok((
        input,
        Data::WriteMultipleRegisters {
            start_address,
            output_count,
            byte_count,
            output_values
        }
    ))
}

fn parse_report_server_id(input: &[u8]) -> IResult<&[u8], Data> {
     let (input, _) = eof(input)?;
     Ok((
         input,
         Data::ReportServerID {}
     ))
}

fn parse_read_file_record(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, byte_count) = u8(input)?;
    let (input, sub_requests) = count(parse_read_file_record_sub_request, byte_count as usize / 7 as usize as usize)(input)?;
    Ok((
        input,
        Data::ReadFileRecord {
            byte_count,
            sub_requests
        }
    ))
}

fn parse_write_file_record(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, byte_count) = u8(input)?;
    let (input, sub_requests) = count(parse_write_file_record_sub_request, byte_count as usize / 7 as usize as usize)(input)?;
    Ok((
        input,
        Data::WriteFileRecord {
            byte_count,
            sub_requests
        }
    ))
}

fn parse_mask_write_register(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, ref_address) = be_u16(input)?;
    let (input, and_mask) = be_u16(input)?;
    let (input, or_mask) = be_u16(input)?;
    Ok((
        input,
        Data::MaskWriteRegister {
            ref_address,
            and_mask,
            or_mask
        }
    ))
}

fn parse_read_write_multiple_registers(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, read_start_address) = be_u16(input)?;
    let (input, read_count) = be_u16(input)?;
    let (input, write_start_address) = be_u16(input)?;
    let (input, write_count) = be_u16(input)?;
    let (input, write_byte_count) = u8(input)?;
    let (input, write_register_values) = take(write_count as usize * 2 as usize)(input)?;
    Ok((
        input,
        Data::ReadWriteMultipleRegisters {
            read_start_address,
            read_count,
            write_start_address,
            write_count,
            write_byte_count,
            write_register_values
        }
    ))
}

fn parse_read_fifo_queue(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, fifo_pointer_address) = be_u16(input)?;
    Ok((
        input,
        Data::ReadFIFOQueue {
            fifo_pointer_address
        }
    ))
}

pub fn parse_data(input: &[u8], function_code: u8) -> IResult<&[u8], Data> {
    let (input, data) = match function_code {
        0x01 => parse_read_coils(input),
        0x02 => parse_read_discre_inputs(input),
        0x03 => parse_read_holding_registers(input),
        0x04 => parse_read_input_registers(input),
        0x05 => parse_write_single_coil(input),
        0x06 => parse_write_single_register(input),
        0x07 => parse_read_exception_status(input),
        0x0b => parse_get_comm_event_counter(input),
        0x0c => parse_get_comm_event_log(input),
        0x0f => parse_write_multiple_coils(input),
        0x10 => parse_write_multiple_registers(input),
        0x11 => parse_report_server_id(input),
        0x14 => parse_read_file_record(input),
        0x15 => parse_write_file_record(input),
        0x16 => parse_mask_write_register(input),
        0x17 => parse_read_write_multiple_registers(input),
        0x18 => parse_read_fifo_queue(input),
        _ =>  Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }?;
    Ok((input, data))
}

pub fn parse_pdu(input: &[u8]) -> IResult<&[u8], PDU> {
    let (input, function_code) = u8(input)?;
    let (input, data) = parse_data(input, function_code)?;
    Ok((
        input,
        PDU {
            function_code,
            data
        }
    ))
}