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
use nom::number::complete::{be_u16, le_u16, be_u24, le_u24, be_u32, le_u32, u8};
#[allow(unused)]
use nom::sequence::tuple;
#[allow(unused)]
use nom::IResult;

#[allow(unused)]
use crate::errors::ParseError;
#[allow(unused)]
use crate::layer::{ApplicationLayer, LinkLayer, NetworkLayer, TransportLayer};
#[allow(unused)]
use crate::packet::{QuinPacket, QuinPacketOptions, L1Packet, L2Packet, L3Packet, L4Packet, L5Packet};
#[allow(unused)]
use crate::ProtocolType;
#[allow(unused)]
use crate::field_type::*;
#[allow(unused)]
use crate::protocol::*;

#[allow(unused)]
use std::ops::BitAnd;
#[allow(unused)]
use std::ops::BitOr;
#[allow(unused)]
use std::ops::BitXor;


use super::parse_l5_eof_layer;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct S7commHeader<'a> {
    pub header: Header,
    pub parameter: Parameter<'a>,
}

pub fn parse_s7comm_header(input: &[u8]) -> IResult<&[u8], S7commHeader> {
    let (input, header) = parse_header(input)?;
    let (input, parameter) = parse_parameter(input, &header)?;
    Ok((
        input,
        S7commHeader {
            header,
            parameter
        }
    ))
}

pub fn parse_s7comm_layer<'a>(input: &'a [u8], link_layer: LinkLayer, network_layer: NetworkLayer<'a>, transport_layer: TransportLayer<'a>, options: &QuinPacketOptions) -> QuinPacket<'a> {
    let current_layertype = ProtocolType::Application(ApplicationProtocol::S7comm);

    let (input, s7comm_header) = match parse_s7comm_header(input) {
        Ok(o) => o,
        Err(_e) => {
            return QuinPacket::L4(
                L4Packet {
                    link_layer,
                    network_layer,
                    transport_layer,
                    error: Some(ParseError::ParsingHeader),
                    remain: input,
                }
            )
        }
    };

    if Some(current_layertype) == options.stop {
        let application_layer = ApplicationLayer::S7comm(s7comm_header);
        return QuinPacket::L5(
            L5Packet {
                link_layer,
                network_layer,
                transport_layer,
                application_layer,
                error: None,
                remain: input,
            }
        )
    };

    let application_layer = ApplicationLayer::S7comm(s7comm_header);
    return parse_l5_eof_layer(input, link_layer, network_layer, transport_layer, application_layer, options);
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum HeaderErrorInfo {
    HeaderRspErrorInfo {
         error_class: u8,
         error_code: u8,
    },
    EmptyErrorInfo {}
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Header {
    pub protocol_id: u8,
    pub rosctr: u8,
    pub redundancy_identification: [u8; 4],
    pub pdu_ref: u16,
    pub parameter_length: u16,
    pub data_length: u16,
    pub header_error_info: HeaderErrorInfo,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DbreadItem {
    pub dbread_length: u8,
    pub dbread_db: u16,
    pub dbread_startadr: u16,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Tia1200Item {
    pub item_content: [u8; 4],
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SyntaxIdEnum {
    S7any {
         transport_size: u8,
         item_length: u16,
         item_db_numer: u16,
         item_area: u8,
         item_address: [u8; 6],
    },
    Dbread {
         num_areas: u8,
         subitems: Vec<DbreadItem>,
    },
    Tia1200 {
         item_reserved1: u8,
         item_area1: u16,
         item_area2: u16,
         item_crc: u32,
         substructure_items: Vec<Tia1200Item>,
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ParamItem {
    pub var_spec_type: u8,
    pub var_spec_length: u8,
    pub var_spec_syntax_id: u8,
    pub syntax_id_enum: SyntaxIdEnum,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RspReadData<'a> {
    pub return_code: u8,
    pub transport_size: u8,
    pub length: u16,
    pub data: &'a [u8],
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RspWriteData {
    pub return_code: u8,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum JobParam<'a> {
    SetupCommunication {
         reserved: u8,
         max_amq_calling: u16,
         max_amq_called: u16,
         pdu_length: u16,
    },
    ReadVar {
         item_count: u8,
         items: Vec<ParamItem>,
    },
    WriteVar {
         item_count: u8,
         items: Vec<ParamItem>,
         standard_items: Vec<RspReadData<'a>>,
    },
    RequestDownload {
         function_status: u8,
         filename_length: u8,
         filename: &'a str,
         length_part2: u8,
         loadmem_len: &'a str,
         mc7code_len: &'a str,
    },
    DownloadBlock {
         function_status: u8,
         filename_length: u8,
         filename: &'a str,
    },
    DownloadEnded {
         function_status: u8,
         error_code: u16,
         filename_length: u8,
         filename: &'a str,
    },
    StartUpload {
         function_status: u8,
         upload_id: u32,
         filename_length: u8,
         filename: &'a str,
    },
    Upload {
         function_status: u8,
         upload_id: u32,
    },
    EndUpload {
         function_status: u8,
         error_code: u16,
         upload_id: u32,
    },
    PiService {
         parameter_block_len: u16,
         parameter_block: &'a [u8],
         string_len: u8,
         service_name: &'a str,
    },
    PlcStop {
         length_part2: u8,
         service_name: &'a str,
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AckdataParam<'a> {
    SetupCommunication {
         reserved: u8,
         max_amq_calling: u16,
         max_amq_called: u16,
         pdu_length: u16,
    },
    ReadVar {
         item_count: u8,
         standard_items: Vec<RspReadData<'a>>,
    },
    WriteVar {
         item_count: u8,
         items: Vec<RspWriteData>,
    },
    RequestDownload {},
    DownloadBlock {
         function_status: u8,
         data_length: u16,
         data: &'a [u8],
    },
    DownloadEnded {},
    StartUpload {
         function_status: u8,
         upload_id: u32,
         blocklen_string_length: u8,
         blocklen: &'a str,
    },
    Upload {
         function_status: u8,
         data_length: u16,
         data: &'a [u8],
    },
    EndUpload {},
    PiService {},
    PlcStop {}
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum UserdataParamInfo {
    ExtraInfo {
         data_unit_ref_num: u8,
         is_last_data_unit: u8,
         error_code: u16,
    },
    EmptyInfo {}
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Parameter<'a> {
    Job {
         function_code: u8,
         job_param: JobParam<'a>,
    },
    Ack {},
    AckData {
         function_code: u8,
         ackdata_param: AckdataParam<'a>,
    },
    Userdata {
         parameter_header: [u8; 6],
         parameter_length: u8,
         method: u8,
         parameter_type: u8,
         function_group: u8,
         subfunction: u8,
         sequence_number: u8,
         userdata_param_info: UserdataParamInfo,
         data_return_code: u8,
         data_transport_size: u8,
         data_length: u16,
         data: &'a [u8],
    }
}

fn parse_header_error_info_header_rsp_error_info(input: &[u8]) -> IResult<&[u8], HeaderErrorInfo> {
    let (input, error_class) = u8(input)?;
    let (input, error_code) = u8(input)?;
    Ok((
        input,
        HeaderErrorInfo::HeaderRspErrorInfo {
            error_class,
            error_code
        }
    ))
}

#[inline(always)]
fn parse_header_error_info_empty_error_info(input: &[u8]) -> IResult<&[u8], HeaderErrorInfo> {
    Ok((
        input,
        HeaderErrorInfo::EmptyErrorInfo {}
    ))   
}

pub fn parse_header_error_info(input: &[u8], rosctr: u8) -> IResult<&[u8], HeaderErrorInfo> {
    let (input, header_error_info) = match (rosctr == 0x02) || (rosctr == 0x03) {
        true => parse_header_error_info_header_rsp_error_info(input),
        false => parse_header_error_info_empty_error_info(input),
        
    }?;
    Ok((input, header_error_info))
}

pub fn parse_header(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, protocol_id) = u8(input)?;
    let (input, rosctr) = u8(input)?;
    let (input, redundancy_identification) = slice_u4_4(input)?;
    let (input, pdu_ref) = be_u16(input)?;
    let (input, parameter_length) = be_u16(input)?;
    let (input, data_length) = be_u16(input)?;
    let (input, header_error_info) = parse_header_error_info(input, rosctr)?;
    Ok((
        input,
        Header {
            protocol_id,
            rosctr,
            redundancy_identification,
            pdu_ref,
            parameter_length,
            data_length,
            header_error_info
        }
    ))
}

pub fn parse_dbread_item(input: &[u8]) -> IResult<&[u8], DbreadItem> {
    let (input, dbread_length) = u8(input)?;
    let (input, dbread_db) = be_u16(input)?;
    let (input, dbread_startadr) = be_u16(input)?;
    Ok((
        input,
        DbreadItem {
            dbread_length,
            dbread_db,
            dbread_startadr
        }
    ))
}

pub fn parse_tia1200_item(input: &[u8]) -> IResult<&[u8], Tia1200Item> {
    let (input, item_content) = slice_u8_4(input)?;
    Ok((
        input,
        Tia1200Item {
            item_content
        }
    ))
}

pub fn parse_syntax_id_enum(input: &[u8], var_spec_length: u8, var_spec_syntax_id: u8) -> IResult<&[u8], SyntaxIdEnum> {
    if var_spec_length == 10 && var_spec_syntax_id == 0x10 {
        let (input, transport_size) = u8(input)?;
        let (input, item_length) = be_u16(input)?;
        let (input, item_db_numer) = be_u16(input)?;
        let (input, item_area) = u8(input)?;
        let (input, item_address) = slice_u4_6(input)?;
        Ok((
            input,
            SyntaxIdEnum::S7any {
                transport_size,
                item_length,
                item_db_numer,
                item_area,
                item_address
            }
        ))
    }
    else if var_spec_length >= 7 && var_spec_syntax_id == 0xb0 {
        let (input, num_areas) = u8(input)?;
        let (input, subitems) = count(parse_dbread_item, num_areas as usize)(input)?;
        Ok((
            input,
            SyntaxIdEnum::Dbread {
                num_areas,
                subitems
            }
        ))
    }
    else if var_spec_length >= 14 && var_spec_syntax_id == 0xb2 {
        let (input, item_reserved1) = u8(input)?;
        let (input, item_area1) = be_u16(input)?;
        let (input, item_area2) = be_u16(input)?;
        let (input, item_crc) = be_u32(input)?;
        let (input, substructure_items) = count(parse_tia1200_item, ((var_spec_length - 10) / 4) as usize)(input)?;
        Ok((
            input,
            SyntaxIdEnum::Tia1200 {
                item_reserved1,
                item_area1,
                item_area2,
                item_crc,
                substructure_items
            }
        ))
    }
    else {
        return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
    }
}

pub fn parse_param_item(input: &[u8]) -> IResult<&[u8], ParamItem> {
    let (input, var_spec_type) = u8(input)?;
    if !(var_spec_type == 0x12) {
        return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
    }
    let (input, var_spec_length) = u8(input)?;
    let (input, var_spec_syntax_id) = u8(input)?;
    let (input, syntax_id_enum) = parse_syntax_id_enum(input, var_spec_length, var_spec_syntax_id)?;
    Ok((
        input,
        ParamItem {
            var_spec_type,
            var_spec_length,
            var_spec_syntax_id,
            syntax_id_enum
        }
    ))
}

pub fn parse_rsp_read_data(input: &[u8]) -> IResult<&[u8], RspReadData> {
    let (input, return_code) = u8(input)?;
    let (input, transport_size) = u8(input)?;
    let (input, length) = be_u16(input)?;
    let mut length_tmp = length;
    if (length_tmp % 8) != 0 {
        length_tmp /= 8;
        length_tmp += 1;
    } else {
        length_tmp /= 8;
    }
    let (input, data) = take(length_tmp as usize)(input)?;
    let mut input = input;
    let mut _fill_byte: u8;
    if (length_tmp % 2 != 0) && (input.len()) != 0 {
        (input, _fill_byte) = u8(input)?;
    }
    Ok((
        input,
        RspReadData {
            return_code,
            transport_size,
            length,
            data
        }
    ))
}

pub fn parse_rsp_write_data(input: &[u8]) -> IResult<&[u8], RspWriteData> {
    let (input, return_code) = u8(input)?;
    Ok((
        input,
        RspWriteData {
            return_code
        }
    ))
}

fn parse_job_param_setup_communication(input: &[u8]) -> IResult<&[u8], JobParam> {
    let (input, reserved) = u8(input)?;
    let (input, max_amq_calling) = be_u16(input)?;
    let (input, max_amq_called) = be_u16(input)?;
    let (input, pdu_length) = be_u16(input)?;
    Ok((
        input,
        JobParam::SetupCommunication {
            reserved,
            max_amq_calling,
            max_amq_called,
            pdu_length
        }
    ))
}

fn parse_job_param_read_var(input: &[u8]) -> IResult<&[u8], JobParam> {
    let (input, item_count) = u8(input)?;
    let (input, items) = count(parse_param_item, item_count as usize)(input)?;
    Ok((
        input,
        JobParam::ReadVar {
            item_count,
            items
        }
    ))
}

fn parse_job_param_write_var(input: &[u8]) -> IResult<&[u8], JobParam> {
    let (input, item_count) = u8(input)?;
    let (input, items) = count(parse_param_item, item_count as usize)(input)?;
    let (input, standard_items) = count(parse_rsp_read_data, item_count as usize)(input)?;
    Ok((
        input,
        JobParam::WriteVar {
            item_count,
            items,
            standard_items
        }
    ))
}

fn parse_job_param_request_download(input: &[u8]) -> IResult<&[u8], JobParam> {
    let (input, function_status) = u8(input)?;
    let (input, _) = take(6 as usize)(input)?;
    let (input, filename_length) = u8(input)?;
    if !(filename_length == 9) {
        return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
    }
    let (input, _filename) = take(filename_length as usize)(input)?;
    let filename = match std::str::from_utf8(_filename) {
        Ok(o) => o,
        Err(_) => return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
    };
    let (input, length_part2) = u8(input)?;
    let (input, _) = take(1 as usize)(input)?;
    let (input, _loadmem_len) = take(6 as usize)(input)?;
    let loadmem_len = match std::str::from_utf8(_loadmem_len) {
        Ok(o) => o,
        Err(_) => return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
    };
    let (input, _mc7code_len) = take(6 as usize)(input)?;
    let mc7code_len = match std::str::from_utf8(_mc7code_len) {
        Ok(o) => o,
        Err(_) => return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
    };
    Ok((
        input,
        JobParam::RequestDownload {
            function_status,
            filename_length,
            filename,
            length_part2,
            loadmem_len,
            mc7code_len
        }
    ))
}

fn parse_job_param_download_block(input: &[u8]) -> IResult<&[u8], JobParam> {
    let (input, function_status) = u8(input)?;
    let (input, _) = take(6 as usize)(input)?;
    let (input, filename_length) = u8(input)?;
    if !(filename_length == 9) {
        return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
    }
    let (input, _filename) = take(filename_length as usize)(input)?;
    let filename = match std::str::from_utf8(_filename) {
        Ok(o) => o,
        Err(_) => return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
    };
    Ok((
        input,
        JobParam::DownloadBlock {
            function_status,
            filename_length,
            filename
        }
    ))
}

fn parse_job_param_download_ended(input: &[u8]) -> IResult<&[u8], JobParam> {
    let (input, function_status) = u8(input)?;
    let (input, error_code) = be_u16(input)?;
    let (input, _) = take(4 as usize)(input)?;
    let (input, filename_length) = u8(input)?;
    if !(filename_length == 9) {
        return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
    }
    let (input, _filename) = take(filename_length as usize)(input)?;
    let filename = match std::str::from_utf8(_filename) {
        Ok(o) => o,
        Err(_) => return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
    };
    Ok((
        input,
        JobParam::DownloadEnded {
            function_status,
            error_code,
            filename_length,
            filename
        }
    ))
}

fn parse_job_param_start_upload(input: &[u8]) -> IResult<&[u8], JobParam> {
    let (input, function_status) = u8(input)?;
    let (input, _) = take(2 as usize)(input)?;
    let (input, upload_id) = be_u32(input)?;
    let (input, filename_length) = u8(input)?;
    if !(filename_length == 9) {
        return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
    }
    let (input, _filename) = take(filename_length as usize)(input)?;
    let filename = match std::str::from_utf8(_filename) {
        Ok(o) => o,
        Err(_) => return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
    };
    Ok((
        input,
        JobParam::StartUpload {
            function_status,
            upload_id,
            filename_length,
            filename
        }
    ))
}

fn parse_job_param_upload(input: &[u8]) -> IResult<&[u8], JobParam> {
    let (input, function_status) = u8(input)?;
    let (input, _) = take(2 as usize)(input)?;
    let (input, upload_id) = be_u32(input)?;
    Ok((
        input,
        JobParam::Upload {
            function_status,
            upload_id
        }
    ))
}

fn parse_job_param_end_upload(input: &[u8]) -> IResult<&[u8], JobParam> {
    let (input, function_status) = u8(input)?;
    let (input, error_code) = be_u16(input)?;
    let (input, upload_id) = be_u32(input)?;
    Ok((
        input,
        JobParam::EndUpload {
            function_status,
            error_code,
            upload_id
        }
    ))
}

fn parse_job_param_pi_service(input: &[u8]) -> IResult<&[u8], JobParam> {
    let (input, _) = take(7 as usize)(input)?;
    let (input, parameter_block_len) = be_u16(input)?;
    let (input, parameter_block) = take(parameter_block_len as usize)(input)?;
    let (input, string_len) = u8(input)?;
    let (input, _service_name) = take(string_len as usize)(input)?;
    let service_name = match std::str::from_utf8(_service_name) {
        Ok(o) => o,
        Err(_) => return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
    };
    Ok((
        input,
        JobParam::PiService {
            parameter_block_len,
            parameter_block,
            string_len,
            service_name
        }
    ))
}

fn parse_job_param_plc_stop(input: &[u8]) -> IResult<&[u8], JobParam> {
    let (input, _) = take(5 as usize)(input)?;
    let (input, length_part2) = u8(input)?;
    let (input, _service_name) = take(length_part2 as usize)(input)?;
    let service_name = match std::str::from_utf8(_service_name) {
        Ok(o) => o,
        Err(_) => return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
    };
    Ok((
        input,
        JobParam::PlcStop {
            length_part2,
            service_name
        }
    ))
}

pub fn parse_job_param(input: &[u8], function_code: u8) -> IResult<&[u8], JobParam> {
    let (input, job_param) = match function_code {
        0xf0 => parse_job_param_setup_communication(input),
        0x04 => parse_job_param_read_var(input),
        0x05 => parse_job_param_write_var(input),
        0x1a => parse_job_param_request_download(input),
        0x1b => parse_job_param_download_block(input),
        0x1c => parse_job_param_download_ended(input),
        0x1d => parse_job_param_start_upload(input),
        0x1e => parse_job_param_upload(input),
        0x1f => parse_job_param_end_upload(input),
        0x28 => parse_job_param_pi_service(input),
        0x29 => parse_job_param_plc_stop(input),
        _ =>  Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }?;
    Ok((input, job_param))
}

fn parse_ackdata_param_setup_communication(input: &[u8]) -> IResult<&[u8], AckdataParam> {
    let (input, reserved) = u8(input)?;
    let (input, max_amq_calling) = be_u16(input)?;
    let (input, max_amq_called) = be_u16(input)?;
    let (input, pdu_length) = be_u16(input)?;
    Ok((
        input,
        AckdataParam::SetupCommunication {
            reserved,
            max_amq_calling,
            max_amq_called,
            pdu_length
        }
    ))
}

fn parse_ackdata_param_read_var(input: &[u8]) -> IResult<&[u8], AckdataParam> {
    let (input, item_count) = u8(input)?;
    let (input, standard_items) = count(parse_rsp_read_data, item_count as usize)(input)?;
    Ok((
        input,
        AckdataParam::ReadVar {
            item_count,
            standard_items
        }
    ))
}

fn parse_ackdata_param_write_var(input: &[u8]) -> IResult<&[u8], AckdataParam> {
    let (input, item_count) = u8(input)?;
    let (input, items) = count(parse_rsp_write_data, item_count as usize)(input)?;
    Ok((
        input,
        AckdataParam::WriteVar {
            item_count,
            items
        }
    ))
}

fn parse_ackdata_param_request_download(input: &[u8]) -> IResult<&[u8], AckdataParam> {
    let (input, _) = eof(input)?;
    Ok((
        input,
        AckdataParam::RequestDownload {}
    ))   
}

fn parse_ackdata_param_download_block(input: &[u8]) -> IResult<&[u8], AckdataParam> {
    let (input, function_status) = u8(input)?;
    let (input, data_length) = be_u16(input)?;
    let (input, _) = take(2 as usize)(input)?;
    let (input, data) = take(data_length as usize)(input)?;
    Ok((
        input,
        AckdataParam::DownloadBlock {
            function_status,
            data_length,
            data
        }
    ))
}

fn parse_ackdata_param_download_ended(input: &[u8]) -> IResult<&[u8], AckdataParam> {
    let (input, _) = eof(input)?;
    Ok((
        input,
        AckdataParam::DownloadEnded {}
    ))   
}

fn parse_ackdata_param_start_upload(input: &[u8]) -> IResult<&[u8], AckdataParam> {
    let (input, function_status) = u8(input)?;
    let (input, _) = take(2 as usize)(input)?;
    let (input, upload_id) = be_u32(input)?;
    let (input, blocklen_string_length) = u8(input)?;
    let (input, _blocklen) = take(blocklen_string_length as usize)(input)?;
    let blocklen = match std::str::from_utf8(_blocklen) {
        Ok(o) => o,
        Err(_) => return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
    };
    Ok((
        input,
        AckdataParam::StartUpload {
            function_status,
            upload_id,
            blocklen_string_length,
            blocklen
        }
    ))
}

fn parse_ackdata_param_upload(input: &[u8]) -> IResult<&[u8], AckdataParam> {
    let (input, function_status) = u8(input)?;
    let (input, data_length) = be_u16(input)?;
    let (input, _) = take(2 as usize)(input)?;
    let (input, data) = take(data_length as usize)(input)?;
    Ok((
        input,
        AckdataParam::Upload {
            function_status,
            data_length,
            data
        }
    ))
}

fn parse_ackdata_param_end_upload(input: &[u8]) -> IResult<&[u8], AckdataParam> {
    let (input, _) = eof(input)?;
    Ok((
        input,
        AckdataParam::EndUpload {}
    ))   
}

fn parse_ackdata_param_pi_service(input: &[u8]) -> IResult<&[u8], AckdataParam> {
    let (input, _) = eof(input)?;
    Ok((
        input,
        AckdataParam::PiService {}
    ))   
}

fn parse_ackdata_param_plc_stop(input: &[u8]) -> IResult<&[u8], AckdataParam> {
    let (input, _) = eof(input)?;
    Ok((
        input,
        AckdataParam::PlcStop {}
    ))   
}

pub fn parse_ackdata_param(input: &[u8], function_code: u8) -> IResult<&[u8], AckdataParam> {
    let (input, ackdata_param) = match function_code {
        0xf0 => parse_ackdata_param_setup_communication(input),
        0x04 => parse_ackdata_param_read_var(input),
        0x05 => parse_ackdata_param_write_var(input),
        0x1a => parse_ackdata_param_request_download(input),
        0x1b => parse_ackdata_param_download_block(input),
        0x1c => parse_ackdata_param_download_ended(input),
        0x1d => parse_ackdata_param_start_upload(input),
        0x1e => parse_ackdata_param_upload(input),
        0x1f => parse_ackdata_param_end_upload(input),
        0x28 => parse_ackdata_param_pi_service(input),
        0x29 => parse_ackdata_param_plc_stop(input),
        _ =>  Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }?;
    Ok((input, ackdata_param))
}

pub fn parse_userdata_param_info(input: &[u8], parameter_length: u16) -> IResult<&[u8], UserdataParamInfo> {
    let (input, userdata_param_info) = match parameter_length {
        0x0c => {
            let (input, data_unit_ref_num) = u8(input)?;
            let (input, is_last_data_unit) = u8(input)?;
            let (input, error_code) = be_u16(input)?;
            Ok((
                input,
                UserdataParamInfo::ExtraInfo {
                    data_unit_ref_num,
                    is_last_data_unit,
                    error_code
                }
            ))
        }
        0x08 => {
            Ok((
                input,
                UserdataParamInfo::EmptyInfo {}
            ))
        }
        _ =>  Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }?;
    Ok((input, userdata_param_info))
}

pub fn parse_parameter<'a>(input: &'a[u8], header: &Header) -> IResult<&'a[u8], Parameter<'a>> {
    let (input, parameter) = match header.rosctr {
        0x01 => {
            let (input, function_code) = u8(input)?;
            let (input, job_param) = parse_job_param(input, function_code)?;
            Ok((
                input,
                Parameter::Job {
                    function_code,
                    job_param
                }
            ))
        }
        0x02 => {
            let (input, _) = eof(input)?;
            Ok((
                input,
                Parameter::Ack {}
            ))
        }
        0x03 => {
            let (input, function_code) = u8(input)?;
            let (input, ackdata_param) = parse_ackdata_param(input, function_code)?;
            Ok((
                input,
                Parameter::AckData {
                    function_code,
                    ackdata_param
                }
            ))
        }
        0x07 => {
            let (input, parameter_header) = slice_u4_6(input)?;
            let (input, parameter_length) = u8(input)?;
            let (input, method) = u8(input)?;
            let (input, (parameter_type, function_group)) = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(4usize), take_bits(4usize)))
            )(input)?;
            let (input, subfunction) = u8(input)?;
            let (input, sequence_number) = u8(input)?;
            let (input, userdata_param_info) = parse_userdata_param_info(input, header.parameter_length)?;
            let (input, data_return_code) = u8(input)?;
            let (input, data_transport_size) = u8(input)?;
            let (input, data_length) = be_u16(input)?;
            let (input, data) = take(data_length as usize)(input)?;
            Ok((
                input,
                Parameter::Userdata {
                    parameter_header,
                    parameter_length,
                    method,
                    parameter_type, function_group,
                    subfunction,
                    sequence_number,
                    userdata_param_info,
                    data_return_code,
                    data_transport_size,
                    data_length,
                    data
                }
            ))
        }
        _ =>  Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }?;
    Ok((input, parameter))
}