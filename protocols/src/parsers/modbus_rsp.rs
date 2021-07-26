use nom::bits::bits;
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::{take};
use nom::combinator::eof;
use nom::multi::count;
use nom::number::complete::{be_u16, u8};
use nom::IResult;
use nom::error::Error;

use crate::layer_type::LayerType;
use crate::{HeaderTrait, PayloadTrait};

#[derive(Debug, PartialEq, Clone)]
pub struct ModbusRspHeader<'a> {
    pub mbap_header: MbapHeader,
    pub pdu: PDU<'a>,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct MbapHeader {
    pub transaction_id: u16,
    pub protocol_id: u16,
    pub length: u16,
    pub unit_id: u8,
}

fn parse_mbap_header(input: &[u8]) -> nom::IResult<&[u8], MbapHeader> {
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
            unit_id,
        },
    ))
}

#[derive(Debug, PartialEq, Clone)]
pub struct PDU<'a> {
    pub function_code: u8,
    pub data: Data<'a>,
}

fn parse_pdu(input: &[u8]) -> IResult<&[u8], PDU> {
    let (input, function_code) = u8(input)?;
    let (input, data) = match function_code {
        0x01 => parse_read_coils(input),
        0x02 => parse_read_discre_inputs(input),
        0x03 => parse_read_holding_registers(input),
        0x04 => parse_read_input_registers(input),
        0x05 => parse_write_single_coil(input),
        0x06 => parse_write_single_register(input),
        0x07 => parse_eof(input),
        0x0b => parse_eof(input),
        0x0c => parse_eof(input),
        0x0f => parse_write_multiple_coils(input),
        0x10 => parse_write_multiple_registers(input),
        0x11 => parse_eof(input),
        0x14 => parse_read_file_record(input),
        0x15 => parse_write_file_record(input),
        0x16 => parse_mask_write_register(input),
        0x17 => parse_read_write_multiple_registers(input),
        0x18 => parse_read_fifo_queue(input),
        0x81 => parse_read_coils_exc(input),
        0x82 => parse_read_discre_inputs_exc(input),
        0x83 => parse_read_holding_registers_exc(input),
        0x84 => parse_read_input_registers_exc(input),
        0x85 => parse_write_single_coil_exc(input),
        0x86 => parse_write_single_register_exc(input),
        0x87 => parse_eof(input),
        0x8b => parse_eof(input),
        0x8c => parse_eof(input),
        0x8f => parse_write_multiple_coils_exc(input),
        0x90 => parse_write_multiple_registers_exc(input),
        0x91 => parse_eof(input),
        0x94 => parse_read_file_record_exc(input),
        0x95 => parse_write_file_record_exc(input),
        0x96 => parse_mask_write_register_exc(input),
        0x97 => parse_read_write_multiple_registers_exc(input),
        0x98 => parse_read_fifo_queue_exc(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((
        input,
        PDU {
            function_code,
            data,
        },
    ))
}

#[derive(Debug, PartialEq, Clone)]
pub enum Data<'a> {
    ReadCoils {
        byte_count: u8,
        coil_status: Vec<u8>,
    },
    ReadDiscreInputs {
        byte_count: u8,
        coil_status: Vec<u8>,
    },
    ReadHoldingRegisters {
        byte_count: u8,
        coil_status: Vec<u16>,
    },
    ReadInputRegisters {
        byte_count: u8,
        coil_status: Vec<u16>,
    },
    WriteSingleCoil {
        output_address: u16,
        output_value: u16,
    },
    WriteSingleRegister {
        register_address: u16,
        register_value: u16,
    },
    WriteMultipleCoils {
        start_address: u16,
        output_count: u16,
    },
    WriteMultipleRegisters {
        start_address: u16,
        output_count: u16,
    },
    Eof {},
    ReadFileRecord {
        byte_count: u8,
        sub_requests: Vec<ReadFileRecordSubRequest<'a>>,
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
        byte_count: u8,
        read_registers_value: &'a [u8],
    },
    ReadFIFOQueue {
        byte_count: u16,
        fifo_count: u16,
        fifo_value_register: &'a [u8],
    },
    ReadCoilsExc {
        exception_code: u8,
    },
    ReadDiscreInputsExc {
        exception_code: u8,
    },
    ReadHoldingRegistersExc {
        exception_code: u8,
    },
    ReadInputRegistersExc {
        exception_code: u8,
    },
    WriteSingleCoilExc {
        exception_code: u8,
    },
    WriteSingleRegisterExc {
        exception_code: u8,
    },
    WriteMultipleCoilsExc {
        exception_code: u8,
    },
    WriteMultipleRegistersExc {
        exception_code: u8,
    },
    ReadFileRecordExc {
        exception_code: u8,
    },
    WriteFileRecordExc {
        exception_code: u8,
    },
    MaskWriteRegisterExc {
        exception_code: u8,
    },
    ReadWriteMultipleRegistersExc {
        exception_code: u8,
    },
    ReadFIFOQueueExc {
        exception_code: u8,
    },
}

fn parse_read_coils(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, byte_count) = u8(input)?;
    let (input, coil_status) = count(u8, byte_count as usize)(input)?;
    Ok((
        input,
        Data::ReadCoils {
            byte_count,
            coil_status,
        },
    ))
}

fn parse_read_discre_inputs(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, byte_count) = u8(input)?;
    let (input, coil_status) = bits::<_, _, Error<(&[u8], usize)>, Error<&[u8]>, _>(count::<_, u8, _, _>(take_bits(1usize), byte_count as usize * 8usize))(input)?;
    Ok((
        input,
        Data::ReadDiscreInputs {
            byte_count,
            coil_status,
        },
    ))
}

fn parse_read_holding_registers(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, byte_count) = u8(input)?;
    let (input, coil_status) = count(be_u16, (byte_count as usize / 2 as usize) as usize)(input)?;
    Ok((
        input,
        Data::ReadHoldingRegisters {
            byte_count,
            coil_status,
        },
    ))
}

fn parse_read_input_registers(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, byte_count) = u8(input)?;
    let (input, coil_status) = count(be_u16, (byte_count as usize / 2 as usize) as usize)(input)?;
    Ok((
        input,
        Data::ReadInputRegisters {
            byte_count,
            coil_status,
        },
    ))
}

fn parse_write_single_coil(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, output_address) = be_u16(input)?;
    let (input, output_value) = be_u16(input)?;
    Ok((
        input,
        Data::WriteSingleCoil {
            output_address,
            output_value,
        },
    ))
}

fn parse_write_single_register(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, register_address) = be_u16(input)?;
    let (input, register_value) = be_u16(input)?;
    Ok((
        input,
        Data::WriteSingleRegister {
            register_address,
            register_value,
        },
    ))
}

fn parse_write_multiple_coils(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, start_address) = be_u16(input)?;
    let (input, output_count) = be_u16(input)?;
    Ok((
        input,
        Data::WriteMultipleCoils {
            start_address,
            output_count,
        },
    ))
}

fn parse_write_multiple_registers(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, start_address) = be_u16(input)?;
    let (input, output_count) = be_u16(input)?;
    Ok((
        input,
        Data::WriteMultipleRegisters {
            start_address,
            output_count,
        },
    ))
}

fn parse_eof(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, _) = eof(input)?;
    Ok((input, Data::Eof {}))
}

fn parse_read_file_record(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, byte_count) = u8(input)?;
    let (input, sub_requests) = count(
        parse_read_file_record_sub_request,
        (byte_count as usize / 4 as usize) as usize,
    )(input)?;
    Ok((
        input,
        Data::ReadFileRecord {
            byte_count,
            sub_requests,
        },
    ))
}

fn parse_write_file_record(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, byte_count) = u8(input)?;
    let (input, sub_requests) = count(
        parse_write_file_record_sub_request,
        (byte_count as usize / 7 as usize) as usize,
    )(input)?;
    Ok((
        input,
        Data::WriteFileRecord {
            byte_count,
            sub_requests,
        },
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
            or_mask,
        },
    ))
}

fn parse_read_write_multiple_registers(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, byte_count) = u8(input)?;
    let (input, read_registers_value) = take(byte_count)(input)?;
    Ok((
        input,
        Data::ReadWriteMultipleRegisters {
            byte_count,
            read_registers_value,
        },
    ))
}

fn parse_read_fifo_queue(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, byte_count) = be_u16(input)?;
    let (input, fifo_count) = be_u16(input)?;
    let (input, fifo_value_register) = take(fifo_count * 2)(input)?;
    Ok((
        input,
        Data::ReadFIFOQueue {
            byte_count,
            fifo_count,
            fifo_value_register,
        },
    ))
}

fn parse_read_coils_exc(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, exception_code) = u8(input)?;
    Ok((input, Data::ReadDiscreInputsExc { exception_code }))
}

fn parse_read_discre_inputs_exc(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, exception_code) = u8(input)?;
    Ok((input, Data::ReadDiscreInputsExc { exception_code }))
}

fn parse_read_holding_registers_exc(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, exception_code) = u8(input)?;
    Ok((input, Data::ReadHoldingRegistersExc { exception_code }))
}

fn parse_read_input_registers_exc(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, exception_code) = u8(input)?;
    Ok((input, Data::ReadInputRegistersExc { exception_code }))
}

fn parse_write_single_coil_exc(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, exception_code) = u8(input)?;
    Ok((input, Data::WriteSingleCoilExc { exception_code }))
}

fn parse_write_single_register_exc(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, exception_code) = u8(input)?;
    Ok((input, Data::WriteSingleRegisterExc { exception_code }))
}

fn parse_write_multiple_coils_exc(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, exception_code) = u8(input)?;
    Ok((input, Data::WriteMultipleCoilsExc { exception_code }))
}

fn parse_write_multiple_registers_exc(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, exception_code) = u8(input)?;
    Ok((input, Data::WriteMultipleRegistersExc { exception_code }))
}

fn parse_read_file_record_exc(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, exception_code) = u8(input)?;
    Ok((input, Data::ReadFileRecordExc { exception_code }))
}

fn parse_write_file_record_exc(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, exception_code) = u8(input)?;
    Ok((input, Data::WriteFileRecordExc { exception_code }))
}

fn parse_mask_write_register_exc(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, exception_code) = u8(input)?;
    Ok((input, Data::MaskWriteRegisterExc { exception_code }))
}

fn parse_read_write_multiple_registers_exc(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, exception_code) = u8(input)?;
    Ok((
        input,
        Data::ReadWriteMultipleRegistersExc { exception_code },
    ))
}

fn parse_read_fifo_queue_exc(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, exception_code) = u8(input)?;
    Ok((input, Data::ReadFIFOQueueExc { exception_code }))
}

#[derive(Debug, PartialEq, Clone)]
pub struct ReadFileRecordSubRequest<'a> {
    pub file_rsp_len: u8,
    pub ref_type: u8,
    pub record_data: &'a [u8],
}

fn parse_read_file_record_sub_request(input: &[u8]) -> IResult<&[u8], ReadFileRecordSubRequest> {
    let (input, file_rsp_len) = u8(input)?;
    let (input, ref_type) = u8(input)?;
    let (input, record_data) = take(file_rsp_len - 1)(input)?;
    Ok((
        input,
        ReadFileRecordSubRequest {
            file_rsp_len,
            ref_type,
            record_data,
        },
    ))
}

#[derive(Debug, PartialEq, Clone)]
pub struct WriteFileRecordSubRequest<'a> {
    pub ref_type: u8,
    pub file_number: u16,
    pub record_number: u16,
    pub record_length: u16,
    pub record_data: &'a [u8],
}

fn parse_write_file_record_sub_request(input: &[u8]) -> IResult<&[u8], WriteFileRecordSubRequest> {
    let (input, ref_type) = u8(input)?;
    let (input, file_number) = be_u16(input)?;
    let (input, record_number) = be_u16(input)?;
    let (input, record_length) = be_u16(input)?;
    let (input, record_data) = take(record_length * 2)(input)?;
    Ok((
        input,
        WriteFileRecordSubRequest {
            ref_type,
            file_number,
            record_number,
            record_length,
            record_data,
        },
    ))
}

use super::eof::EofHeader;

#[derive(Debug, PartialEq)]
pub enum ModbusRspPayload<'a> {
    Eof(EofHeader),
    Unknown(&'a [u8]),
    Error(ModbusRspPayloadError<'a>),
}

#[derive(Debug, PartialEq)]
pub enum ModbusRspPayloadError<'a> {
    Eof(&'a [u8]),
    NomPeek(&'a [u8]),
}

impl<'a> HeaderTrait<'a> for ModbusRspHeader<'a> {
    fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, mbap_header) = parse_mbap_header(input)?;
        let (input, pdu) = parse_pdu(input)?;
        Ok((input, ModbusRspHeader { mbap_header, pdu }))
    }

    fn get_type(&self) -> LayerType {
        return LayerType::ModbusRsp
    }
}

impl<'a> PayloadTrait<'a> for ModbusRspPayload<'a> {
    type Header = ModbusRspHeader<'a>;

    fn parse(
        input: &'a [u8],
        _header: &Self::Header,
    ) -> nom::IResult<&'a [u8], Self> {
        match input.len() {
            0 => match EofHeader::parse(input) {
                Ok((input, eof)) => Ok((input, ModbusRspPayload::Eof(eof))),
                Err(_) => Ok((input, ModbusRspPayload::Error(ModbusRspPayloadError::Eof(input)))),
            },
            _ => Ok((input, ModbusRspPayload::Unknown(input))),
        }
    }
}