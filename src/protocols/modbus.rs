use nom::bits::bits;
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::{tag, take};
use nom::multi::count;
use nom::combinator::eof;
use nom::number::complete::{be_u32, be_u16, u8};
use nom::IResult;

#[derive(Debug, PartialEq)]
pub struct MBAPHeader {
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
pub enum Request<'a> {
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
    Eof {},
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
pub enum Payload<'a> {
    Request(Request<'a>),
    Exception {
         exception_code: u8,
    }
}

#[derive(Debug, PartialEq)]
pub struct ModbusPacket<'a> {
    pub header: MBAPHeader,
    pub function_code: u8,
    pub payload: Payload<'a>,
}

pub fn parse_mbap_header(input: &[u8]) -> IResult<&[u8], MBAPHeader> {
    let (input, transaction_id) = be_u16(input)?;
    let (input, protocol_id) = be_u16(input)?;
    let (input, length) = be_u16(input)?;
    let (input, unit_id) = u8(input)?;
    Ok((
        input,
        MBAPHeader {
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
    let (input, record_data) = take(record_length)(input)?;
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

fn parse_read_coils(input: &[u8]) -> IResult<&[u8], Request> {
    let (input, start_address) = be_u16(input)?;
    let (input, count) = be_u16(input)?;
    Ok((
        input,
        Request::ReadCoils {
            start_address,
            count
        }
    ))
}

fn parse_read_discre_inputs(input: &[u8]) -> IResult<&[u8], Request> {
    let (input, start_address) = be_u16(input)?;
    let (input, count) = be_u16(input)?;
    Ok((
        input,
        Request::ReadDiscreInputs {
            start_address,
            count
        }
    ))
}

fn parse_read_holding_registers(input: &[u8]) -> IResult<&[u8], Request> {
    let (input, start_address) = be_u16(input)?;
    let (input, count) = be_u16(input)?;
    Ok((
        input,
        Request::ReadHoldingRegisters {
            start_address,
            count
        }
    ))
}

fn parse_read_input_registers(input: &[u8]) -> IResult<&[u8], Request> {
    let (input, start_address) = be_u16(input)?;
    let (input, count) = be_u16(input)?;
    Ok((
        input,
        Request::ReadInputRegisters {
            start_address,
            count
        }
    ))
}

fn parse_write_single_coil(input: &[u8]) -> IResult<&[u8], Request> {
    let (input, output_address) = be_u16(input)?;
    let (input, output_value) = be_u16(input)?;
    Ok((
        input,
        Request::WriteSingleCoil {
            output_address,
            output_value
        }
    ))
}

fn parse_write_single_register(input: &[u8]) -> IResult<&[u8], Request> {
    let (input, register_address) = be_u16(input)?;
    let (input, register_value) = be_u16(input)?;
    Ok((
        input,
        Request::WriteSingleRegister {
            register_address,
            register_value
        }
    ))
}

fn parse_write_multiple_coils(input: &[u8]) -> IResult<&[u8], Request> {
    let (input, start_address) = be_u16(input)?;
    let (input, output_count) = be_u16(input)?;
    let (input, byte_count) = u8(input)?;
    let (input, output_values) = count(u8, output_count as usize)(input)?;
    Ok((
        input,
        Request::WriteMultipleCoils {
            start_address,
            output_count,
            byte_count,
            output_values
        }
    ))
}

fn parse_write_multiple_registers(input: &[u8]) -> IResult<&[u8], Request> {
    let (input, start_address) = be_u16(input)?;
    let (input, output_count) = be_u16(input)?;
    let (input, byte_count) = u8(input)?;
    let (input, output_values) = count(be_u16, (output_count * 2) as usize)(input)?;
    Ok((
        input,
        Request::WriteMultipleRegisters {
            start_address,
            output_count,
            byte_count,
            output_values
        }
    ))
}

fn parse_eof(input: &[u8]) -> IResult<&[u8], Request> {
     let (input, _) = eof(input)?;
     Ok((
         input,
         Request::Eof {}
     ))
}

fn parse_read_file_record(input: &[u8]) -> IResult<&[u8], Request> {
    let (input, byte_count) = u8(input)?;
    let (input, sub_requests) = count(parse_read_file_record_sub_request, (byte_count as usize / 7 as usize) as usize)(input)?;
    Ok((
        input,
        Request::ReadFileRecord {
            byte_count,
            sub_requests
        }
    ))
}

fn parse_write_file_record(input: &[u8]) -> IResult<&[u8], Request> {
    let (input, byte_count) = u8(input)?;
    let (input, sub_requests) = count(parse_write_file_record_sub_request, (byte_count as usize / 7 as usize) as usize)(input)?;
    Ok((
        input,
        Request::WriteFileRecord {
            byte_count,
            sub_requests
        }
    ))
}

fn parse_mask_write_register(input: &[u8]) -> IResult<&[u8], Request> {
    let (input, ref_address) = be_u16(input)?;
    let (input, and_mask) = be_u16(input)?;
    let (input, or_mask) = be_u16(input)?;
    Ok((
        input,
        Request::MaskWriteRegister {
            ref_address,
            and_mask,
            or_mask
        }
    ))
}

fn parse_read_write_multiple_registers(input: &[u8]) -> IResult<&[u8], Request> {
    let (input, read_start_address) = be_u16(input)?;
    let (input, read_count) = be_u16(input)?;
    let (input, write_start_address) = be_u16(input)?;
    let (input, write_count) = be_u16(input)?;
    let (input, write_byte_count) = u8(input)?;
    let (input, write_register_values) = take((write_count * 2))(input)?;
    Ok((
        input,
        Request::ReadWriteMultipleRegisters {
            read_start_address,
            read_count,
            write_start_address,
            write_count,
            write_byte_count,
            write_register_values
        }
    ))
}

fn parse_read_fifo_queue(input: &[u8]) -> IResult<&[u8], Request> {
    let (input, fifo_pointer_address) = be_u16(input)?;
    Ok((
        input,
        Request::ReadFIFOQueue {
            fifo_pointer_address
        }
    ))
}

pub fn parse_request(input: &[u8], function_code: u8) -> IResult<&[u8], Request> {
    let (input, request) = match function_code {
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
        _ =>  Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }?;
    Ok((input, request))
}

fn parse_exception(input: &[u8]) -> IResult<&[u8], Payload> {
    let (input, exception_code) = u8(input)?;
    Ok((
        input,
        Payload::Exception {
            exception_code
        }
    ))
}

pub fn parse_payload(input: &[u8], function_code: u8) -> IResult<&[u8], Payload> {
    let (input, payload) = match function_code & 0b10000000 {
        0x0 => {
            let (input, request) = parse_request(input, function_code)?;
            Ok((input, Payload::Request(request)))
        },
        0x01 => parse_exception(input),
        _ =>  Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }?;
    Ok((input, payload))
}

pub fn parse_modbus_packet(input: &[u8]) -> IResult<&[u8], ModbusPacket> {
    let (input, header) = parse_mbap_header(input)?;
    let (input, function_code) = u8(input)?;
    let (input, payload) = parse_payload(input, function_code)?;
    Ok((
        input,
        ModbusPacket {
            header,
            function_code,
            payload
        }
    ))
}