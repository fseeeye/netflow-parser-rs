use nom::bytes::complete::take;
use nom::combinator::eof;
use nom::multi::count;
use nom::number::complete::{be_u16, u8};
use nom::IResult;

use crate::errors::ParseError;
use crate::layer::{LinkLayer, NetworkLayer, TransportLayer, ApplicationLayer};
use crate::packet_quin::{L4Packet, QuinPacket, QuinPacketOptions};

use super::parse_l5_eof_layer;


#[derive(Debug, PartialEq, Clone)]
pub struct ModbusReqHeader<'a> {
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
    let (input, data) = parse_data(input, function_code)?;
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
    },
}

fn parse_data(input: &[u8], function_code: u8) -> IResult<&[u8], Data> {
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
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, data))
}

fn parse_read_coils(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, start_address) = be_u16(input)?;
    let (input, count) = be_u16(input)?;
    Ok((
        input,
        Data::ReadCoils {
            start_address,
            count,
        },
    ))
}

fn parse_read_discre_inputs(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, start_address) = be_u16(input)?;
    let (input, count) = be_u16(input)?;
    Ok((
        input,
        Data::ReadDiscreInputs {
            start_address,
            count,
        },
    ))
}

fn parse_read_holding_registers(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, start_address) = be_u16(input)?;
    let (input, count) = be_u16(input)?;
    Ok((
        input,
        Data::ReadHoldingRegisters {
            start_address,
            count,
        },
    ))
}

fn parse_read_input_registers(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, start_address) = be_u16(input)?;
    let (input, count) = be_u16(input)?;
    Ok((
        input,
        Data::ReadInputRegisters {
            start_address,
            count,
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
    let (input, byte_count) = u8(input)?;
    let (input, output_values) = count(u8, output_count as usize)(input)?;
    Ok((
        input,
        Data::WriteMultipleCoils {
            start_address,
            output_count,
            byte_count,
            output_values,
        },
    ))
}

fn parse_write_multiple_registers(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, start_address) = be_u16(input)?;
    let (input, output_count) = be_u16(input)?;
    let (input, byte_count) = u8(input)?;
    let (input, output_values) = count(be_u16, (output_count * 2) as usize)(input)?;
    Ok((
        input,
        Data::WriteMultipleRegisters {
            start_address,
            output_count,
            byte_count,
            output_values,
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
        (byte_count as usize / 7 as usize) as usize,
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
    let (input, read_start_address) = be_u16(input)?;
    let (input, read_count) = be_u16(input)?;
    let (input, write_start_address) = be_u16(input)?;
    let (input, write_count) = be_u16(input)?;
    let (input, write_byte_count) = u8(input)?;
    let (input, write_register_values) = take(write_count * 2)(input)?;
    Ok((
        input,
        Data::ReadWriteMultipleRegisters {
            read_start_address,
            read_count,
            write_start_address,
            write_count,
            write_byte_count,
            write_register_values,
        },
    ))
}

fn parse_read_fifo_queue(input: &[u8]) -> IResult<&[u8], Data> {
    let (input, fifo_pointer_address) = be_u16(input)?;
    Ok((
        input,
        Data::ReadFIFOQueue {
            fifo_pointer_address,
        },
    ))
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct ReadFileRecordSubRequest {
    pub ref_type: u8,
    pub file_number: u16,
    pub record_number: u16,
    pub record_length: u16,
}

fn parse_read_file_record_sub_request(input: &[u8]) -> IResult<&[u8], ReadFileRecordSubRequest> {
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
            record_length,
        },
    ))
}

#[derive(Debug, PartialEq, Clone, Copy)]
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

pub fn parse_modbus_req_header(input: &[u8]) -> nom::IResult<&[u8], ModbusReqHeader> {
    let (input, mbap_header) = parse_mbap_header(input)?;
    let (input, pdu) = parse_pdu(input)?;
    Ok((input, ModbusReqHeader { mbap_header, pdu }))
}

pub(crate) fn parse_modbus_req_layer<'a>(input: &'a [u8], link_layer: LinkLayer, net_layer: NetworkLayer<'a>, trans_layer: TransportLayer<'a>, options: QuinPacketOptions) -> QuinPacket<'a> {
    let (input, modbus_req) = match parse_modbus_req_header(input) {
        Ok(o) => o,
        Err(_e) => {
            return QuinPacket::L4(
                L4Packet {
                    link_layer,
                    net_layer,
                    trans_layer,
                    remain: input,
                    error: Some(ParseError::ParsingHeader),
                }
            )
        }
    };

    let app_layer = ApplicationLayer::ModbusReq(modbus_req);
    parse_l5_eof_layer(input, link_layer, net_layer, trans_layer, app_layer, options)
}
