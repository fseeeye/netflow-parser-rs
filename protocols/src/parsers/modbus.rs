use nom::bits::bits;
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::{tag, take};
use nom::multi::count;
use nom::combinator::eof;
use nom::sequence::tuple;
use nom::number::complete::{be_u32, be_u16, u8};
use nom::IResult;

use crate::traits::PacketTrait; // changed
use super::parser_context::ParserContext; // added

#[derive(Debug, PartialEq)]
pub struct Modbus<'a> {
    pub mbap_header: MbapHeader,
    pub data: Data<'a>
}

#[derive(Debug, PartialEq)]
pub struct MbapHeader {
    pub transaction_id: u16,
    pub protocol_id: u16,
    pub length: u16,
    pub unit_id: u8,
    pub function_code: u8
}

#[derive(Debug, PartialEq)]
pub struct ReadFileRecordReqSubRequest {
    pub ref_type: u8,
    pub file_number: u16,
    pub record_number: u16,
    pub record_length: u16,
}

#[derive(Debug, PartialEq)]
pub struct ReadFileRecordRspSubRequest<'a> {
    pub file_rsp_len: u8,
    pub ref_type: u8,
    pub record_data: &'a [u8],
}

#[derive(Debug, PartialEq)]
pub struct WriteFileRecordReqSubRequest<'a> {
    pub ref_type: u8,
    pub file_number: u16,
    pub record_number: u16,
    pub record_length: u16,
    pub record_data: &'a [u8],
}

#[derive(Debug, PartialEq)]
pub enum ResponseOrExc<'a> {
    Response(Response<'a>),
    Exception {
         exception_code: u8,
    }
}

#[derive(Debug, PartialEq)]
pub enum Response<'a> {
    ReadCoilsRsp {
         byte_count: u8,
         coil_status: Vec<u8>,
    },
    ReadDiscreInputsRsp {
         byte_count: u8,
         coil_status: Vec<u8>,
    },
    ReadHoldingRegistersRsp {
         byte_count: u8,
         coil_status: Vec<u16>,
    },
    ReadInputRegistersRsp {
         byte_count: u8,
         coil_status: Vec<u16>,
    },
    WriteSingleCoilRsp {
         output_address: u16,
         output_value: u16,
    },
    WriteSingleRegisterRsp {
         register_address: u16,
         register_value: u16,
    },
    WriteMultipleCoilsRsp {
         start_address: u16,
         output_count: u16,
    },
    WriteMultipleRegistersRsp {
         start_address: u16,
         output_count: u16,
    },
    Eof {},
    ReadFileRecordRsp {
         byte_count: u8,
         sub_requests: Vec<ReadFileRecordRspSubRequest<'a>>,
    },
    WriteFileRecordRsp {
         byte_count: u8,
         sub_requests: Vec<WriteFileRecordReqSubRequest<'a>>,
    },
    MaskWriteRegisterRsp {
         ref_address: u16,
         and_mask: u16,
         or_mask: u16,
    },
    ReadWriteMultipleRegistersRsp {
         byte_count: u8,
         read_registers_value: &'a [u8],
    },
    ReadFIFOQueueRsp {
         byte_count: u16,
         fifo_count: u16,
         fifo_value_register: &'a [u8],
    }
}

#[derive(Debug, PartialEq)]
pub enum Request<'a> {
    ReadCoilsReq {
         start_address: u16,
         count: u16,
    },
    ReadDiscreInputsReq {
         start_address: u16,
         count: u16,
    },
    ReadHoldingRegistersReq {
         start_address: u16,
         count: u16,
    },
    ReadInputRegistersReq {
         start_address: u16,
         count: u16,
    },
    WriteSingleCoilReq {
         output_address: u16,
         output_value: u16,
    },
    WriteSingleRegisterReq {
         register_address: u16,
         register_value: u16,
    },
    WriteMultipleCoilsReq {
         start_address: u16,
         output_count: u16,
         byte_count: u8,
         output_values: Vec<u8>,
    },
    WriteMultipleRegistersReq {
         start_address: u16,
         output_count: u16,
         byte_count: u8,
         output_values: Vec<u16>,
    },
    Eof {},
    ReadFileRecordReq {
         byte_count: u8,
         sub_requests: Vec<ReadFileRecordReqSubRequest>,
    },
    WriteFileRecordReq {
         byte_count: u8,
         sub_requests: Vec<WriteFileRecordReqSubRequest<'a>>,
    },
    MaskWriteRegisterReq {
         ref_address: u16,
         and_mask: u16,
         or_mask: u16,
    },
    ReadWriteMultipleRegistersReq {
         read_start_address: u16,
         read_count: u16,
         write_start_address: u16,
         write_count: u16,
         write_byte_count: u8,
         write_register_values: &'a [u8],
    },
    ReadFIFOQueueReq {
         fifo_pointer_address: u16,
    }
}

#[derive(Debug, PartialEq)]
pub enum Data<'a> {
    Request(Request<'a>),
    ResponseOrExc(ResponseOrExc<'a>)
}

use crate::parsers::eof;

#[derive(Debug, PartialEq)]
pub enum ModbusPayloadError {
    NotEof,
}

#[derive(Debug, PartialEq)]
pub enum ModbusPayload<'a> {
    Eof(eof::Eof<'a>),
    Unknown(&'a [u8]),
    Error(ModbusPayloadError),
}

#[derive(Debug, PartialEq)]
pub struct ModbusPacket<'a> {
    pub header: Modbus<'a>,
    pub payload: ModbusPayload<'a>
}


pub fn parse_read_file_record_req_sub_request<'a>(input: &'a [u8]) -> IResult<&'a [u8], ReadFileRecordReqSubRequest> { // added: lifetime! // Q: if add lifetiem judge // error!
    let (input, ref_type) = u8(input)?;
    let (input, file_number) = be_u16(input)?;
    let (input, record_number) = be_u16(input)?;
    let (input, record_length) = be_u16(input)?;
    Ok((
        input,
        ReadFileRecordReqSubRequest {
            ref_type,
            file_number,
            record_number,
            record_length
        }
    ))
}

pub fn parse_read_file_record_rsp_sub_request<'a>(input: &'a [u8]) -> IResult<&'a [u8], ReadFileRecordRspSubRequest<'a>> { // error!
    let (input, file_rsp_len) = u8(input)?;
    let (input, ref_type) = u8(input)?;
    let (input, record_data) = take(file_rsp_len - 1)(input)?;
    Ok((
        input,
        ReadFileRecordRspSubRequest {
            file_rsp_len,
            ref_type,
            record_data
        }
    ))
}

pub fn parse_write_file_record_req_sub_request<'a>(input: &'a [u8]) -> IResult<&'a [u8], WriteFileRecordReqSubRequest<'a>> { // error!
    let (input, ref_type) = u8(input)?;
    let (input, file_number) = be_u16(input)?;
    let (input, record_number) = be_u16(input)?;
    let (input, record_length) = be_u16(input)?;
    let (input, record_data) = take((record_length * 2))(input)?;
    Ok((
        input,
        WriteFileRecordReqSubRequest {
            ref_type,
            file_number,
            record_number,
            record_length,
            record_data
        }
    ))
}

fn parse_exception<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], ResponseOrExc<'a>> {
    let (input, exception_code) = u8(input)?;
    Ok((
        input,
        ResponseOrExc::Exception {
            exception_code
        }
    ))
}

pub fn parse_response_or_exc<'a>(input: &'a [u8], header: &MbapHeader, _context: &ParserContext) -> IResult<&'a [u8], ResponseOrExc<'a>> {
    let (input, response_or_exc) = match header.function_code & 0b1000_0000 {
        0x0 => {
            let (input, response) = parse_response(input, &header, _context)?;
            Ok((input, ResponseOrExc::Response(response)))
        },
        0x01 => parse_exception(input, _context),
        _ =>  Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }?;
    Ok((input, response_or_exc))
}

fn parse_read_coils_rsp<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Response<'a>> {
    let (input, byte_count) = u8(input)?;
    let (input, coil_status) = count(u8, byte_count as usize)(input)?;
    Ok((
        input,
        Response::ReadCoilsRsp {
            byte_count,
            coil_status
        }
    ))
}

fn parse_read_discre_inputs_rsp<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Response<'a>> {
    let (input, byte_count) = u8(input)?;
    let (input, coil_status) = count(u8, byte_count as usize)(input)?;
    Ok((
        input,
        Response::ReadDiscreInputsRsp {
            byte_count,
            coil_status
        }
    ))
}

fn parse_read_holding_registers_rsp<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Response<'a>> {
    let (input, byte_count) = u8(input)?;
    let (input, coil_status) = count(be_u16, (byte_count as usize / 2 as usize) as usize)(input)?;
    Ok((
        input,
        Response::ReadHoldingRegistersRsp {
            byte_count,
            coil_status
        }
    ))
}

fn parse_read_input_registers_rsp<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Response<'a>> {
    let (input, byte_count) = u8(input)?;
    let (input, coil_status) = count(be_u16, (byte_count as usize / 2 as usize) as usize)(input)?;
    Ok((
        input,
        Response::ReadInputRegistersRsp {
            byte_count,
            coil_status
        }
    ))
}

fn parse_write_single_coil_rsp<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Response<'a>> {
    let (input, output_address) = be_u16(input)?;
    let (input, output_value) = be_u16(input)?;
    Ok((
        input,
        Response::WriteSingleCoilRsp {
            output_address,
            output_value
        }
    ))
}

fn parse_write_single_register_rsp<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Response<'a>> {
    let (input, register_address) = be_u16(input)?;
    let (input, register_value) = be_u16(input)?;
    Ok((
        input,
        Response::WriteSingleRegisterRsp {
            register_address,
            register_value
        }
    ))
}

fn parse_write_multiple_coils_rsp<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Response<'a>> {
    let (input, start_address) = be_u16(input)?;
    let (input, output_count) = be_u16(input)?;
    Ok((
        input,
        Response::WriteMultipleCoilsRsp {
            start_address,
            output_count
        }
    ))
}

fn parse_write_multiple_registers_rsp<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Response<'a>> {
    let (input, start_address) = be_u16(input)?;
    let (input, output_count) = be_u16(input)?;
    Ok((
        input,
        Response::WriteMultipleRegistersRsp {
            start_address,
            output_count
        }
    ))
}

// fix
fn parse_rsp_eof<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Response<'a>> {
     let (input, _) = eof(input)?;
     Ok((
         input,
         Response::Eof {}
     ))
}

fn parse_read_file_record_rsp<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Response<'a>> {
    let (input, byte_count) = u8(input)?;
    let (input, sub_requests) = count(parse_read_file_record_rsp_sub_request, (byte_count as usize / 4 as usize) as usize)(input)?;
    Ok((
        input,
        Response::ReadFileRecordRsp {
            byte_count,
            sub_requests
        }
    ))
}

fn parse_write_file_record_rsp<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Response<'a>> {
    let (input, byte_count) = u8(input)?;
    let (input, sub_requests) = count(parse_write_file_record_req_sub_request, (byte_count as usize / 7 as usize) as usize)(input)?;
    Ok((
        input,
        Response::WriteFileRecordRsp {
            byte_count,
            sub_requests
        }
    ))
}

fn parse_mask_write_register_rsp<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Response<'a>> {
    let (input, ref_address) = be_u16(input)?;
    let (input, and_mask) = be_u16(input)?;
    let (input, or_mask) = be_u16(input)?;
    Ok((
        input,
        Response::MaskWriteRegisterRsp {
            ref_address,
            and_mask,
            or_mask
        }
    ))
}

fn parse_read_write_multiple_registers_rsp<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Response<'a>> {
    let (input, byte_count) = u8(input)?;
    let (input, read_registers_value) = take(byte_count)(input)?;
    Ok((
        input,
        Response::ReadWriteMultipleRegistersRsp {
            byte_count,
            read_registers_value
        }
    ))
}

fn parse_read_fifo_queue_rsp<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Response<'a>> {
    let (input, byte_count) = be_u16(input)?;
    let (input, fifo_count) = be_u16(input)?;
    let (input, fifo_value_register) = take((fifo_count * 2))(input)?;
    Ok((
        input,
        Response::ReadFIFOQueueRsp {
            byte_count,
            fifo_count,
            fifo_value_register
        }
    ))
}

pub fn parse_response<'a>(input: &'a [u8], header: &MbapHeader, _context: &ParserContext) -> IResult<&'a [u8], Response<'a>> {
    let (input, response) = match header.function_code {
        0x01 => parse_read_coils_rsp(input, _context),
        0x02 => parse_read_discre_inputs_rsp(input, _context),
        0x03 => parse_read_holding_registers_rsp(input, _context),
        0x04 => parse_read_input_registers_rsp(input, _context),
        0x05 => parse_write_single_coil_rsp(input, _context),
        0x06 => parse_write_single_register_rsp(input, _context),
        0x07 => parse_rsp_eof(input, _context), // fix
        0x0b => parse_rsp_eof(input, _context), // fix
        0x0c => parse_rsp_eof(input, _context), // fix
        0x0f => parse_write_multiple_coils_rsp(input, _context),
        0x10 => parse_write_multiple_registers_rsp(input, _context),
        0x11 => parse_rsp_eof(input, _context), // fix
        0x14 => parse_read_file_record_rsp(input, _context),
        0x15 => parse_write_file_record_rsp(input, _context),
        0x16 => parse_mask_write_register_rsp(input, _context),
        0x17 => parse_read_write_multiple_registers_rsp(input, _context),
        0x18 => parse_read_fifo_queue_rsp(input, _context),
        _ =>  Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }?;
    Ok((input, response))
}

fn parse_read_coils_req<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Request<'a>> {
    let (input, start_address) = be_u16(input)?;
    let (input, count) = be_u16(input)?;
    Ok((
        input,
        Request::ReadCoilsReq {
            start_address,
            count
        }
    ))
}

fn parse_read_discre_inputs_req<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Request<'a>> {
    let (input, start_address) = be_u16(input)?;
    let (input, count) = be_u16(input)?;
    Ok((
        input,
        Request::ReadDiscreInputsReq {
            start_address,
            count
        }
    ))
}

fn parse_read_holding_registers_req<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Request<'a>> {
    let (input, start_address) = be_u16(input)?;
    let (input, count) = be_u16(input)?;
    Ok((
        input,
        Request::ReadHoldingRegistersReq {
            start_address,
            count
        }
    ))
}

fn parse_read_input_registers_req<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Request<'a>> {
    let (input, start_address) = be_u16(input)?;
    let (input, count) = be_u16(input)?;
    Ok((
        input,
        Request::ReadInputRegistersReq {
            start_address,
            count
        }
    ))
}

fn parse_write_single_coil_req<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Request<'a>> {
    let (input, output_address) = be_u16(input)?;
    let (input, output_value) = be_u16(input)?;
    Ok((
        input,
        Request::WriteSingleCoilReq {
            output_address,
            output_value
        }
    ))
}

fn parse_write_single_register_req<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Request<'a>> {
    let (input, register_address) = be_u16(input)?;
    let (input, register_value) = be_u16(input)?;
    Ok((
        input,
        Request::WriteSingleRegisterReq {
            register_address,
            register_value
        }
    ))
}

fn parse_write_multiple_coils_req<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Request<'a>> {
    let (input, start_address) = be_u16(input)?;
    let (input, output_count) = be_u16(input)?;
    let (input, byte_count) = u8(input)?;
    let (input, output_values) = count(u8, output_count as usize)(input)?;
    Ok((
        input,
        Request::WriteMultipleCoilsReq {
            start_address,
            output_count,
            byte_count,
            output_values
        }
    ))
}

fn parse_write_multiple_registers_req<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Request<'a>> {
    let (input, start_address) = be_u16(input)?;
    let (input, output_count) = be_u16(input)?;
    let (input, byte_count) = u8(input)?;
    let (input, output_values) = count(be_u16, (output_count * 2) as usize)(input)?;
    Ok((
        input,
        Request::WriteMultipleRegistersReq {
            start_address,
            output_count,
            byte_count,
            output_values
        }
    ))
}

// fix
fn parse_req_eof<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Request<'a>> {
     let (input, _) = eof(input)?;
     Ok((
         input,
         Request::Eof {}
     ))
}

fn parse_read_file_record_req<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Request<'a>> {
    let (input, byte_count) = u8(input)?;
    let (input, sub_requests) = count(parse_read_file_record_req_sub_request, (byte_count as usize / 7 as usize) as usize)(input)?;
    Ok((
        input,
        Request::ReadFileRecordReq {
            byte_count,
            sub_requests
        }
    ))
}

fn parse_write_file_record_req<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Request<'a>> {
    let (input, byte_count) = u8(input)?;
    let (input, sub_requests) = count(parse_write_file_record_req_sub_request, (byte_count as usize / 7 as usize) as usize)(input)?;
    Ok((
        input,
        Request::WriteFileRecordReq {
            byte_count,
            sub_requests
        }
    ))
}

fn parse_mask_write_register_req<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Request<'a>> {
    let (input, ref_address) = be_u16(input)?;
    let (input, and_mask) = be_u16(input)?;
    let (input, or_mask) = be_u16(input)?;
    Ok((
        input,
        Request::MaskWriteRegisterReq {
            ref_address,
            and_mask,
            or_mask
        }
    ))
}

fn parse_read_write_multiple_registers_req<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Request<'a>> {
    let (input, read_start_address) = be_u16(input)?;
    let (input, read_count) = be_u16(input)?;
    let (input, write_start_address) = be_u16(input)?;
    let (input, write_count) = be_u16(input)?;
    let (input, write_byte_count) = u8(input)?;
    let (input, write_register_values) = take((write_count * 2))(input)?;
    Ok((
        input,
        Request::ReadWriteMultipleRegistersReq {
            read_start_address,
            read_count,
            write_start_address,
            write_count,
            write_byte_count,
            write_register_values
        }
    ))
}

fn parse_read_fifo_queue_req<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], Request<'a>> {
    let (input, fifo_pointer_address) = be_u16(input)?;
    Ok((
        input,
        Request::ReadFIFOQueueReq {
            fifo_pointer_address
        }
    ))
}

pub fn parse_request<'a>(input: &'a [u8], header: &MbapHeader, _context: &ParserContext) -> IResult<&'a [u8], Request<'a>> {
    let (input, request) = match header.function_code {
        0x01 => parse_read_coils_req(input, _context),
        0x02 => parse_read_discre_inputs_req(input, _context),
        0x03 => parse_read_holding_registers_req(input, _context),
        0x04 => parse_read_input_registers_req(input, _context),
        0x05 => parse_write_single_coil_req(input, _context),
        0x06 => parse_write_single_register_req(input, _context),
        0x07 => parse_req_eof(input, _context), // fix
        0x0b => parse_req_eof(input, _context), // fix
        0x0c => parse_req_eof(input, _context), // fix
        0x0f => parse_write_multiple_coils_req(input, _context),
        0x10 => parse_write_multiple_registers_req(input, _context),
        0x11 => parse_req_eof(input, _context), // fix
        0x14 => parse_read_file_record_req(input, _context),
        0x15 => parse_write_file_record_req(input, _context),
        0x16 => parse_mask_write_register_req(input, _context),
        0x17 => parse_read_write_multiple_registers_req(input, _context),
        0x18 => parse_read_fifo_queue_req(input, _context),
        _ =>  Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }?;
    Ok((input, request))
}

pub fn parse_mbap_header<'a>(input: &'a [u8], _context: &ParserContext) -> IResult<&'a [u8], MbapHeader> {
    let (input, transaction_id) = be_u16(input)?;
    let (input, protocol_id) = be_u16(input)?;
    let (input, length) = be_u16(input)?;
    let (input, unit_id) = u8(input)?;
    let (input, function_code) = u8(input)?;
    Ok((
        input,
        MbapHeader {
            transaction_id,
            protocol_id,
            length,
            unit_id,
            function_code
        }
    ))
}

// warning
pub fn parse_data<'a>(input: &'a [u8], header: &MbapHeader, _context: &ParserContext) -> IResult<&'a [u8], Data<'a>> {
    let (input, data) = match _context.src_port { // Q: if?
        Some(502) => {
            let (input, response) = parse_response_or_exc(input, &header, _context)?;
            Ok((input, Data::ResponseOrExc(response)))
        },
        None => Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
        _ => match _context.dst_port {
            Some(502) => {
                let (input, request) = parse_request(input, &header, _context)?;
                Ok((input, Data::Request(request)))
            },
            None => Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
            _ => Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
        }
    }?;
    Ok((input, data))
}

impl<'a> PacketTrait<'a> for ModbusPacket<'a> {
    type Header = Modbus<'a>;
    type Payload = ModbusPayload<'a>;
	type PayloadError = ModbusPayloadError;
	
	fn parse_header(input: &'a [u8], _context: &mut ParserContext) -> IResult<&'a [u8], Self::Header> {
        let (input, mbap_header) = parse_mbap_header(input, _context)?;
        let (input, data) = parse_data(input, &mbap_header, _context)?;
        Ok((
            input,
            Modbus {
                mbap_header,
                data
            }
        ))
    }

	fn parse_payload(input: &'a [u8], _header: &Self::Header, context: &mut ParserContext) -> IResult<&'a [u8], Self::Payload> {
        use super::eof::Eof;
        match Eof::parse(input, context) {
            Ok((input, eof)) => Ok((input, Self::Payload::Eof(eof))),
            Err(_) => Ok((input, Self::Payload::Error(Self::PayloadError::NotEof)))
        }
    }

	fn parse(input: &'a [u8], context: &mut ParserContext) -> nom::IResult<&'a [u8], Self> {
        let (input, header) = Self::parse_header(input, context)?;
        let (input, payload) = Self::parse_payload(input, &header, context)?;
        Ok((
            input,
            ModbusPacket {
                header,
                payload
            }
        ))
    }
}