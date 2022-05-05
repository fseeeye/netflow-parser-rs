#[allow(unused)]
use nom::bits::bits;
#[allow(unused)]
use nom::bits::complete::take as take_bits;
#[allow(unused)]
use nom::bytes::complete::{tag, take};
#[allow(unused)]
use nom::combinator::{eof, map, peek};
#[allow(unused)]
use nom::error::{Error, ErrorKind};
#[allow(unused)]
use nom::multi::count;
#[allow(unused)]
use nom::number::complete::{be_u16, be_u24, be_u32, u8};
#[allow(unused)]
use nom::sequence::tuple;
#[allow(unused)]
use nom::IResult;

#[allow(unused)]
use crate::errors::ParseError;
#[allow(unused)]
use crate::field_type::*;
#[allow(unused)]
use crate::layer::{ApplicationLayer, LinkLayer, NetworkLayer, TransportLayer};
#[allow(unused)]
use crate::packet::{
    L1Packet, L2Packet, L3Packet, L4Packet, L5Packet, QuinPacket, QuinPacketOptions,
};
use crate::protocol::ApplicationProtocol;
#[allow(unused)]
use crate::ProtocolType;

use super::parse_l5_eof_layer;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct FinsUdpReqHeader<'a> {
    pub fram_info: u8,
    pub sys_save: u8,
    pub gateway: u8,
    pub dna: u8,
    pub dnn: u8,
    pub dua: u8,
    pub sna: u8,
    pub snn: u8,
    pub sua: u8,
    pub sid: u8,
    pub cmd_type: CmdType<'a>,
}

pub fn parse_fins_udp_req_header(input: &[u8]) -> IResult<&[u8], FinsUdpReqHeader> {
    let (input, fram_info) = u8(input)?;
    let (input, sys_save) = u8(input)?;
    let (input, gateway) = u8(input)?;
    let (input, dna) = u8(input)?;
    let (input, dnn) = u8(input)?;
    let (input, dua) = u8(input)?;
    let (input, sna) = u8(input)?;
    let (input, snn) = u8(input)?;
    let (input, sua) = u8(input)?;
    let (input, sid) = u8(input)?;
    let (input, cmd_type) = parse_cmd_type(input)?;
    Ok((
        input,
        FinsUdpReqHeader {
            fram_info,
            sys_save,
            gateway,
            dna,
            dnn,
            dua,
            sna,
            snn,
            sua,
            sid,
            cmd_type,
        },
    ))
}

pub fn parse_fins_udp_req_layer<'a>(
    input: &'a [u8],
    link_layer: LinkLayer,
    network_layer: NetworkLayer<'a>,
    transport_layer: TransportLayer<'a>,
    options: &QuinPacketOptions,
) -> QuinPacket<'a> {
    let current_prototype = ProtocolType::Application(ApplicationProtocol::FinsUdpReq);

    let (input, fins_udp_req_header) = match parse_fins_udp_req_header(input) {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(
                target: "PARSER(fins_udp_req::parse_fins_udp_req_layer)",
                error = ?e
            );

            let offset = match e {
                nom::Err::Error(error) => input.len() - error.input.len(),
                _ => usize::MAX
            };

            return QuinPacket::L4(L4Packet {
                link_layer,
                network_layer,
                transport_layer,
                error: Some(ParseError::ParsingHeader{
                    protocol: current_prototype,
                    offset
                }),
                remain: input,
            })
        }
    };

    if Some(current_prototype) == options.stop {
        let application_layer = ApplicationLayer::FinsUdpReq(fins_udp_req_header);
        return QuinPacket::L5(L5Packet {
            link_layer,
            network_layer,
            transport_layer,
            application_layer,
            error: None,
            remain: input,
        });
    };

    let application_layer = ApplicationLayer::FinsUdpReq(fins_udp_req_header);
    return parse_l5_eof_layer(
        input,
        link_layer,
        network_layer,
        transport_layer,
        application_layer,
        options,
    );
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MultipleMemoryAreaReadItem {
    pub memory_area_code: u8,
    pub beginning_address: u16,
    pub beginning_address_bits: u8,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DLTBLockDataItem {
    pub status_and_link_nodes: u8,
    pub cio_area_first_word: u16,
    pub kind_od_dm: u8,
    pub dm_area_first_word: u16,
    pub number_of_total_words: u16,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ForcedSetOrResetDataItem {
    pub specification: u16,
    pub memory_area_code: u8,
    pub bit_or_filg: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Order<'a> {
    MemoryAreaRead {
        memory_area_code: u8,
        beginning_address: u16,
        beginning_address_bits: u8,
        number_of_items: u16,
    },
    MemoryAreaWrite {
        memory_area_code: u8,
        beginning_address: u16,
        beginning_address_bits: u8,
        number_of_items: u16,
        command_data: &'a [u8],
    },
    MemoryAreaFill {
        memory_area_code: u8,
        beginning_address: u16,
        beginning_address_bits: u8,
        number_of_items: u16,
        command_data: u16,
    },
    MultipleMemoryAreaRead {
        result: Vec<MultipleMemoryAreaReadItem>,
    },
    MemoryAreaTransfer {
        memory_area_code_wc: u8,
        beginning_address: u16,
        beginning_address_bits: u8,
        memory_area_code_pv: u8,
        beginning_address_pv: u16,
        beginning_address_bits_pv: u8,
        number_of_items: u16,
    },
    ParameterAreaRead {
        parameter_area_code: u16,
        beginning_word: u16,
        words_of_bytes: u16,
    },
    ParameterAreaWrite {
        parameter_area_code: u16,
        beginning_word: u32,
        words_of_bytes: u16,
        command_data: &'a [u8],
    },
    DataLinkTableRead {
        fixed: u16,
        intelligent_id: u16,
        first_word: u16,
        read_length: u16,
    },
    DataLinkTableWrite {
        fixed: u16,
        intelligent_id: u16,
        first_word: u16,
        read_length: u16,
        link_nodes: u8,
        block_data: Vec<DLTBLockDataItem>,
    },
    ParameterAreaClear {
        parameter_area_code: u16,
        beginning_word: u16,
        words_of_bytes: u16,
        command_data: &'a [u8],
    },
    ParameterAreaProtect {
        parameter_number: u16,
        protect_code: u8,
        beginning_word: u32,
        last_word: u32,
        pass_word: u32,
    },
    ParameterAreaProtectClear {
        parameter_number: u16,
        protect_code: u8,
        beginning_word: u32,
        last_word: u32,
        pass_word: u32,
    },
    ProgramAreaRead {
        program_number: u16,
        beginning_word: u32,
        words_of_bytes: u16,
    },
    ProgramAreaWrite {
        program_number: u16,
        beginning_word: u32,
        words_of_bytes: u16,
        command_data: &'a [u8],
    },
    ProgramAreaClear {
        program_number: u16,
        clear_code: u8,
    },
    Run {
        program_number: u16,
        mode_code: &'a [u8],
    },
    Stop {},
    ControllerDataRead {
        command_data: &'a [u8],
    },
    ConnectionDataRead {
        unit_address: u8,
        number_of_units: &'a [u8],
    },
    ControllerStatusRead {},
    DataLinkStatusRead {},
    CycleTimeRead {
        initializes_cycle_time: u8,
    },
    ClcokRead {},
    ClcokWrite {
        year: u8,
        month: u8,
        date: u8,
        hour: u8,
        minute: u8,
        second_and_day: &'a [u8],
    },
    LoopBackTest {
        data: &'a [u8],
    },
    BroadcastTestResultsRead {},
    BroadcastTestDataSend {
        data: &'a [u8],
    },
    MessageReadClearFALSRead {
        message: u16,
    },
    AccessRightAcquire {
        program_number: u16,
    },
    AccessRightForcedAcquire {
        program_number: u16,
    },
    AccessRightRelease {
        program_number: u16,
    },
    ErrorClear {
        error_reset_fal: u16,
    },
    ErrorLogRead {
        beginning_record: u16,
        record_numbers: u16,
    },
    ErrorLogClear {},
    FileNameRead {
        disk_number: u16,
        beginning_file_position: u16,
        number_of_files: u16,
    },
    SingleFileRead {
        disk_number: u16,
        file_name: &'a [u8],
        file_position: u32,
        data_length: u16,
    },
    SingleFileWrite {
        disk_number: u16,
        parameter_code: u16,
        file_name: &'a [u8],
        file_position: u32,
        data_length: u16,
        file_data: &'a [u8],
    },
    MemoryCardFormat {
        disk_number: u16,
    },
    FileDelete {
        disk_number: u16,
        number_of_files: u16,
        file_names: &'a [u8],
    },
    VolumeLabelCreateOrDelete {
        disk_number: u16,
        volume_parameter_code: u16,
        volume_label: &'a [u8],
    },
    FileCopy {
        disk_number_src: u16,
        file_name_src: &'a [u8],
        disk_number_dst: u16,
        file_name_dst: &'a [u8],
    },
    FileNameChange {
        disk_number_src: u16,
        file_name_new: &'a [u8],
        file_name_old: &'a [u8],
    },
    FileDataCheck {
        disk_number: u16,
        file_name: &'a [u8],
    },
    MemoryAreaFileTransfer {
        parameter_code: u16,
        memory_area_code: u8,
        beginning_address: u32,
        number_of_items: u16,
        disk_number: u16,
        file_name: &'a [u8],
    },
    ParameterAreaFileTransfer {
        parameter_code: u16,
        parameter_area_code: u16,
        beginning_address: u16,
        number_of_word_or_bytes: u16,
        disk_number: u16,
        file_name: &'a [u8],
    },
    ProgramAreaFileTransfer {
        parameter_code: u16,
        program_number: u16,
        beginning_address: u32,
        number_of_word_or_bytes: u32,
        disk_number: u16,
        file_name: &'a [u8],
    },
    FileMemoryIndexRead {
        beginning_block_number: u16,
        number_of_blocks: u8,
    },
    FileMemoryRead {
        block_number: u16,
    },
    FileMemoryWrite {
        data_type: u8,
        contral_data: u8,
        block_number: u16,
        file_name: &'a [u8],
    },
    ForcedSetOrReset {
        number_of_bits_flags: u16,
        data: Vec<ForcedSetOrResetDataItem>,
    },
    ForcedSetOrResetCancel {},
    MultipleForcedStatusRead {
        memory_area_code: u8,
        beginning_address: u32,
        number_of_units: u16,
    },
    NameSet {
        name_data: &'a [u8],
    },
    NameDelete {},
    NameRead {},
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CmdType<'a> {
    pub cmd_code: u16,
    pub order: Order<'a>,
}

pub fn parse_multiple_memory_area_read_item(
    input: &[u8],
) -> IResult<&[u8], MultipleMemoryAreaReadItem> {
    let (input, memory_area_code) = u8(input)?;
    let (input, beginning_address) = be_u16(input)?;
    let (input, beginning_address_bits) = u8(input)?;
    Ok((
        input,
        MultipleMemoryAreaReadItem {
            memory_area_code,
            beginning_address,
            beginning_address_bits,
        },
    ))
}

pub fn parse_dltb_lock_data_item(input: &[u8]) -> IResult<&[u8], DLTBLockDataItem> {
    let (input, status_and_link_nodes) = u8(input)?;
    let (input, cio_area_first_word) = be_u16(input)?;
    let (input, kind_od_dm) = u8(input)?;
    let (input, dm_area_first_word) = be_u16(input)?;
    let (input, number_of_total_words) = be_u16(input)?;
    Ok((
        input,
        DLTBLockDataItem {
            status_and_link_nodes,
            cio_area_first_word,
            kind_od_dm,
            dm_area_first_word,
            number_of_total_words,
        },
    ))
}

pub fn parse_forced_set_or_reset_data_item(
    input: &[u8],
) -> IResult<&[u8], ForcedSetOrResetDataItem> {
    let (input, specification) = be_u16(input)?;
    let (input, memory_area_code) = u8(input)?;
    let (input, bit_or_filg) = be_u24(input)?;
    Ok((
        input,
        ForcedSetOrResetDataItem {
            specification,
            memory_area_code,
            bit_or_filg,
        },
    ))
}

fn parse_memory_area_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, memory_area_code) = u8(input)?;
    let (input, beginning_address) = be_u16(input)?;
    let (input, beginning_address_bits) = u8(input)?;
    let (input, number_of_items) = be_u16(input)?;
    Ok((
        input,
        Order::MemoryAreaRead {
            memory_area_code,
            beginning_address,
            beginning_address_bits,
            number_of_items,
        },
    ))
}

fn parse_memory_area_write(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, memory_area_code) = u8(input)?;
    let (input, beginning_address) = be_u16(input)?;
    let (input, beginning_address_bits) = u8(input)?;
    let (input, number_of_items) = be_u16(input)?;
    let (input, command_data) = take(input.len() as usize)(input)?;
    Ok((
        input,
        Order::MemoryAreaWrite {
            memory_area_code,
            beginning_address,
            beginning_address_bits,
            number_of_items,
            command_data,
        },
    ))
}

fn parse_memory_area_fill(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, memory_area_code) = u8(input)?;
    let (input, beginning_address) = be_u16(input)?;
    let (input, beginning_address_bits) = u8(input)?;
    let (input, number_of_items) = be_u16(input)?;
    let (input, command_data) = be_u16(input)?;
    Ok((
        input,
        Order::MemoryAreaFill {
            memory_area_code,
            beginning_address,
            beginning_address_bits,
            number_of_items,
            command_data,
        },
    ))
}

fn parse_multiple_memory_area_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, result) = count(
        parse_multiple_memory_area_read_item,
        (input.len() as usize / 4 as usize) as usize,
    )(input)?;
    Ok((input, Order::MultipleMemoryAreaRead { result }))
}

fn parse_memory_area_transfer(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, memory_area_code_wc) = u8(input)?;
    let (input, beginning_address) = be_u16(input)?;
    let (input, beginning_address_bits) = u8(input)?;
    let (input, memory_area_code_pv) = u8(input)?;
    let (input, beginning_address_pv) = be_u16(input)?;
    let (input, beginning_address_bits_pv) = u8(input)?;
    let (input, number_of_items) = be_u16(input)?;
    Ok((
        input,
        Order::MemoryAreaTransfer {
            memory_area_code_wc,
            beginning_address,
            beginning_address_bits,
            memory_area_code_pv,
            beginning_address_pv,
            beginning_address_bits_pv,
            number_of_items,
        },
    ))
}

fn parse_parameter_area_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, parameter_area_code) = be_u16(input)?;
    let (input, beginning_word) = be_u16(input)?;
    let (input, words_of_bytes) = be_u16(input)?;
    Ok((
        input,
        Order::ParameterAreaRead {
            parameter_area_code,
            beginning_word,
            words_of_bytes,
        },
    ))
}

fn parse_parameter_area_write(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, parameter_area_code) = be_u16(input)?;
    let (input, beginning_word) = be_u32(input)?;
    let (input, words_of_bytes) = be_u16(input)?;
    let (input, command_data) = take(input.len() as usize)(input)?;
    Ok((
        input,
        Order::ParameterAreaWrite {
            parameter_area_code,
            beginning_word,
            words_of_bytes,
            command_data,
        },
    ))
}

fn parse_data_link_table_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, fixed) = be_u16(input)?;
    let (input, intelligent_id) = be_u16(input)?;
    let (input, first_word) = be_u16(input)?;
    let (input, read_length) = be_u16(input)?;
    Ok((
        input,
        Order::DataLinkTableRead {
            fixed,
            intelligent_id,
            first_word,
            read_length,
        },
    ))
}

fn parse_data_link_table_write(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, fixed) = be_u16(input)?;
    let (input, intelligent_id) = be_u16(input)?;
    let (input, first_word) = be_u16(input)?;
    let (input, read_length) = be_u16(input)?;
    let (input, link_nodes) = u8(input)?;
    let (input, block_data) = count(
        parse_dltb_lock_data_item,
        (input.len() as usize / 8 as usize) as usize,
    )(input)?;
    Ok((
        input,
        Order::DataLinkTableWrite {
            fixed,
            intelligent_id,
            first_word,
            read_length,
            link_nodes,
            block_data,
        },
    ))
}

fn parse_parameter_area_clear(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, parameter_area_code) = be_u16(input)?;
    let (input, beginning_word) = be_u16(input)?;
    let (input, words_of_bytes) = be_u16(input)?;
    let (input, command_data) = take(input.len() as usize)(input)?;
    Ok((
        input,
        Order::ParameterAreaClear {
            parameter_area_code,
            beginning_word,
            words_of_bytes,
            command_data,
        },
    ))
}

fn parse_parameter_area_protect(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, parameter_number) = be_u16(input)?;
    let (input, protect_code) = u8(input)?;
    let (input, beginning_word) = be_u32(input)?;
    let (input, last_word) = be_u32(input)?;
    let (input, pass_word) = be_u32(input)?;
    Ok((
        input,
        Order::ParameterAreaProtect {
            parameter_number,
            protect_code,
            beginning_word,
            last_word,
            pass_word,
        },
    ))
}

fn parse_parameter_area_protect_clear(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, parameter_number) = be_u16(input)?;
    let (input, protect_code) = u8(input)?;
    let (input, beginning_word) = be_u32(input)?;
    let (input, last_word) = be_u32(input)?;
    let (input, pass_word) = be_u32(input)?;
    Ok((
        input,
        Order::ParameterAreaProtectClear {
            parameter_number,
            protect_code,
            beginning_word,
            last_word,
            pass_word,
        },
    ))
}

fn parse_program_area_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, program_number) = be_u16(input)?;
    let (input, beginning_word) = be_u32(input)?;
    let (input, words_of_bytes) = be_u16(input)?;
    Ok((
        input,
        Order::ProgramAreaRead {
            program_number,
            beginning_word,
            words_of_bytes,
        },
    ))
}

fn parse_program_area_write(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, program_number) = be_u16(input)?;
    let (input, beginning_word) = be_u32(input)?;
    let (input, words_of_bytes) = be_u16(input)?;
    let (input, command_data) = take(input.len() as usize)(input)?;
    Ok((
        input,
        Order::ProgramAreaWrite {
            program_number,
            beginning_word,
            words_of_bytes,
            command_data,
        },
    ))
}

fn parse_program_area_clear(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, program_number) = be_u16(input)?;
    let (input, clear_code) = u8(input)?;
    Ok((
        input,
        Order::ProgramAreaClear {
            program_number,
            clear_code,
        },
    ))
}

fn parse_run(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, program_number) = be_u16(input)?;
    let (input, mode_code) = take(input.len() as usize)(input)?;
    Ok((
        input,
        Order::Run {
            program_number,
            mode_code,
        },
    ))
}

fn parse_stop(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, _) = eof(input)?;
    Ok((input, Order::Stop {}))
}

fn parse_controller_data_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, command_data) = take(input.len() as usize)(input)?;
    Ok((input, Order::ControllerDataRead { command_data }))
}

fn parse_connection_data_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, unit_address) = u8(input)?;
    let (input, number_of_units) = take(input.len() as usize)(input)?;
    Ok((
        input,
        Order::ConnectionDataRead {
            unit_address,
            number_of_units,
        },
    ))
}

fn parse_controller_status_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, _) = eof(input)?;
    Ok((input, Order::ControllerStatusRead {}))
}

fn parse_data_link_status_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, _) = eof(input)?;
    Ok((input, Order::DataLinkStatusRead {}))
}

fn parse_cycle_time_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, initializes_cycle_time) = u8(input)?;
    Ok((
        input,
        Order::CycleTimeRead {
            initializes_cycle_time,
        },
    ))
}

fn parse_clcok_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, _) = eof(input)?;
    Ok((input, Order::ClcokRead {}))
}

fn parse_clcok_write(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, year) = u8(input)?;
    let (input, month) = u8(input)?;
    let (input, date) = u8(input)?;
    let (input, hour) = u8(input)?;
    let (input, minute) = u8(input)?;
    let (input, second_and_day) = take(input.len() as usize)(input)?;
    Ok((
        input,
        Order::ClcokWrite {
            year,
            month,
            date,
            hour,
            minute,
            second_and_day,
        },
    ))
}

fn parse_loop_back_test(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, data) = take(input.len() as usize)(input)?;
    Ok((input, Order::LoopBackTest { data }))
}

fn parse_broadcast_test_results_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, _) = eof(input)?;
    Ok((input, Order::BroadcastTestResultsRead {}))
}

fn parse_broadcast_test_data_send(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, data) = take(input.len() as usize)(input)?;
    Ok((input, Order::BroadcastTestDataSend { data }))
}

fn parse_message_read_clear_fals_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, message) = be_u16(input)?;
    Ok((input, Order::MessageReadClearFALSRead { message }))
}

fn parse_access_right_acquire(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, program_number) = be_u16(input)?;
    Ok((input, Order::AccessRightAcquire { program_number }))
}

fn parse_access_right_forced_acquire(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, program_number) = be_u16(input)?;
    Ok((input, Order::AccessRightForcedAcquire { program_number }))
}

fn parse_access_right_release(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, program_number) = be_u16(input)?;
    Ok((input, Order::AccessRightRelease { program_number }))
}

fn parse_error_clear(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, error_reset_fal) = be_u16(input)?;
    Ok((input, Order::ErrorClear { error_reset_fal }))
}

fn parse_error_log_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, beginning_record) = be_u16(input)?;
    let (input, record_numbers) = be_u16(input)?;
    Ok((
        input,
        Order::ErrorLogRead {
            beginning_record,
            record_numbers,
        },
    ))
}

fn parse_error_log_clear(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, _) = eof(input)?;
    Ok((input, Order::ErrorLogClear {}))
}

fn parse_file_name_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, disk_number) = be_u16(input)?;
    let (input, beginning_file_position) = be_u16(input)?;
    let (input, number_of_files) = be_u16(input)?;
    Ok((
        input,
        Order::FileNameRead {
            disk_number,
            beginning_file_position,
            number_of_files,
        },
    ))
}

fn parse_single_file_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, disk_number) = be_u16(input)?;
    let (input, file_name) = take(12 as usize)(input)?;
    let (input, file_position) = be_u32(input)?;
    let (input, data_length) = be_u16(input)?;
    Ok((
        input,
        Order::SingleFileRead {
            disk_number,
            file_name,
            file_position,
            data_length,
        },
    ))
}

fn parse_single_file_write(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, disk_number) = be_u16(input)?;
    let (input, parameter_code) = be_u16(input)?;
    let (input, file_name) = take(12 as usize)(input)?;
    let (input, file_position) = be_u32(input)?;
    let (input, data_length) = be_u16(input)?;
    let (input, file_data) = take(data_length as usize)(input)?;
    Ok((
        input,
        Order::SingleFileWrite {
            disk_number,
            parameter_code,
            file_name,
            file_position,
            data_length,
            file_data,
        },
    ))
}

fn parse_memory_card_format(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, disk_number) = be_u16(input)?;
    Ok((input, Order::MemoryCardFormat { disk_number }))
}

fn parse_file_delete(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, disk_number) = be_u16(input)?;
    let (input, number_of_files) = be_u16(input)?;
    let (input, file_names) = take((number_of_files as usize * 12 as usize) as usize)(input)?;
    Ok((
        input,
        Order::FileDelete {
            disk_number,
            number_of_files,
            file_names,
        },
    ))
}

fn parse_volume_label_create_or_delete(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, disk_number) = be_u16(input)?;
    let (input, volume_parameter_code) = be_u16(input)?;
    let (input, volume_label) = take(input.len() as usize)(input)?;
    Ok((
        input,
        Order::VolumeLabelCreateOrDelete {
            disk_number,
            volume_parameter_code,
            volume_label,
        },
    ))
}

fn parse_file_copy(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, disk_number_src) = be_u16(input)?;
    let (input, file_name_src) = take(12 as usize)(input)?;
    let (input, disk_number_dst) = be_u16(input)?;
    let (input, file_name_dst) = take(12 as usize)(input)?;
    Ok((
        input,
        Order::FileCopy {
            disk_number_src,
            file_name_src,
            disk_number_dst,
            file_name_dst,
        },
    ))
}

fn parse_file_name_change(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, disk_number_src) = be_u16(input)?;
    let (input, file_name_new) = take(12 as usize)(input)?;
    let (input, file_name_old) = take(12 as usize)(input)?;
    Ok((
        input,
        Order::FileNameChange {
            disk_number_src,
            file_name_new,
            file_name_old,
        },
    ))
}

fn parse_file_data_check(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, disk_number) = be_u16(input)?;
    let (input, file_name) = take(12 as usize)(input)?;
    Ok((
        input,
        Order::FileDataCheck {
            disk_number,
            file_name,
        },
    ))
}

fn parse_memory_area_file_transfer(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, parameter_code) = be_u16(input)?;
    let (input, memory_area_code) = u8(input)?;
    let (input, beginning_address) = be_u24(input)?;
    let (input, number_of_items) = be_u16(input)?;
    let (input, disk_number) = be_u16(input)?;
    let (input, file_name) = take(12 as usize)(input)?;
    Ok((
        input,
        Order::MemoryAreaFileTransfer {
            parameter_code,
            memory_area_code,
            beginning_address,
            number_of_items,
            disk_number,
            file_name,
        },
    ))
}

fn parse_parameter_area_file_transfer(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, parameter_code) = be_u16(input)?;
    let (input, parameter_area_code) = be_u16(input)?;
    let (input, beginning_address) = be_u16(input)?;
    let (input, number_of_word_or_bytes) = be_u16(input)?;
    let (input, disk_number) = be_u16(input)?;
    let (input, file_name) = take(12 as usize)(input)?;
    Ok((
        input,
        Order::ParameterAreaFileTransfer {
            parameter_code,
            parameter_area_code,
            beginning_address,
            number_of_word_or_bytes,
            disk_number,
            file_name,
        },
    ))
}

fn parse_program_area_file_transfer(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, parameter_code) = be_u16(input)?;
    let (input, program_number) = be_u16(input)?;
    let (input, beginning_address) = be_u32(input)?;
    let (input, number_of_word_or_bytes) = be_u32(input)?;
    let (input, disk_number) = be_u16(input)?;
    let (input, file_name) = take(12 as usize)(input)?;
    Ok((
        input,
        Order::ProgramAreaFileTransfer {
            parameter_code,
            program_number,
            beginning_address,
            number_of_word_or_bytes,
            disk_number,
            file_name,
        },
    ))
}

fn parse_file_memory_index_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, beginning_block_number) = be_u16(input)?;
    let (input, number_of_blocks) = u8(input)?;
    Ok((
        input,
        Order::FileMemoryIndexRead {
            beginning_block_number,
            number_of_blocks,
        },
    ))
}

fn parse_file_memory_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, block_number) = be_u16(input)?;
    Ok((input, Order::FileMemoryRead { block_number }))
}

fn parse_file_memory_write(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, data_type) = u8(input)?;
    let (input, contral_data) = u8(input)?;
    let (input, block_number) = be_u16(input)?;
    let (input, file_name) = take(input.len() as usize)(input)?;
    Ok((
        input,
        Order::FileMemoryWrite {
            data_type,
            contral_data,
            block_number,
            file_name,
        },
    ))
}

fn parse_forced_set_or_reset(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, number_of_bits_flags) = be_u16(input)?;
    let (input, data) = count(
        parse_forced_set_or_reset_data_item,
        (input.len() as usize / 6 as usize) as usize,
    )(input)?;
    Ok((
        input,
        Order::ForcedSetOrReset {
            number_of_bits_flags,
            data,
        },
    ))
}

fn parse_forced_set_or_reset_cancel(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, _) = eof(input)?;
    Ok((input, Order::ForcedSetOrResetCancel {}))
}

fn parse_multiple_forced_status_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, memory_area_code) = u8(input)?;
    let (input, beginning_address) = be_u24(input)?;
    let (input, number_of_units) = be_u16(input)?;
    Ok((
        input,
        Order::MultipleForcedStatusRead {
            memory_area_code,
            beginning_address,
            number_of_units,
        },
    ))
}

fn parse_name_set(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, name_data) = take(input.len() as usize)(input)?;
    Ok((input, Order::NameSet { name_data }))
}

fn parse_name_delete(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, _) = eof(input)?;
    Ok((input, Order::NameDelete {}))
}

fn parse_name_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, _) = eof(input)?;
    Ok((input, Order::NameRead {}))
}

pub fn parse_order(input: &[u8], cmd_code: u16) -> IResult<&[u8], Order> {
    let (input, order) = match cmd_code {
        0x0101 => parse_memory_area_read(input),
        0x0102 => parse_memory_area_write(input),
        0x0103 => parse_memory_area_fill(input),
        0x0104 => parse_multiple_memory_area_read(input),
        0x0105 => parse_memory_area_transfer(input),
        0x0201 => parse_parameter_area_read(input),
        0x0202 => parse_parameter_area_write(input),
        0x0220 => parse_data_link_table_read(input),
        0x0221 => parse_data_link_table_write(input),
        0x0203 => parse_parameter_area_clear(input),
        0x0304 => parse_parameter_area_protect(input),
        0x0305 => parse_parameter_area_protect_clear(input),
        0x0306 => parse_program_area_read(input),
        0x0307 => parse_program_area_write(input),
        0x0308 => parse_program_area_clear(input),
        0x0401 => parse_run(input),
        0x0402 => parse_stop(input),
        0x0501 => parse_controller_data_read(input),
        0x0502 => parse_connection_data_read(input),
        0x0601 => parse_controller_status_read(input),
        0x0603 => parse_data_link_status_read(input),
        0x0620 => parse_cycle_time_read(input),
        0x0701 => parse_clcok_read(input),
        0x0702 => parse_clcok_write(input),
        0x0801 => parse_loop_back_test(input),
        0x0802 => parse_broadcast_test_results_read(input),
        0x0803 => parse_broadcast_test_data_send(input),
        0x0920 => parse_message_read_clear_fals_read(input),
        0x0c01 => parse_access_right_acquire(input),
        0x0c02 => parse_access_right_forced_acquire(input),
        0x0c03 => parse_access_right_release(input),
        0x2101 => parse_error_clear(input),
        0x2102 => parse_error_log_read(input),
        0x2103 => parse_error_log_clear(input),
        0x2201 => parse_file_name_read(input),
        0x2202 => parse_single_file_read(input),
        0x2203 => parse_single_file_write(input),
        0x2204 => parse_memory_card_format(input),
        0x2205 => parse_file_delete(input),
        0x2206 => parse_volume_label_create_or_delete(input),
        0x2207 => parse_file_copy(input),
        0x2208 => parse_file_name_change(input),
        0x2209 => parse_file_data_check(input),
        0x220a => parse_memory_area_file_transfer(input),
        0x220b => parse_parameter_area_file_transfer(input),
        0x220c => parse_program_area_file_transfer(input),
        0x220f => parse_file_memory_index_read(input),
        0x2210 => parse_file_memory_read(input),
        0x2211 => parse_file_memory_write(input),
        0x2301 => parse_forced_set_or_reset(input),
        0x2302 => parse_forced_set_or_reset_cancel(input),
        0x230a => parse_multiple_forced_status_read(input),
        0x2601 => parse_name_set(input),
        0x2602 => parse_name_delete(input),
        0x2603 => parse_name_read(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, order))
}

pub fn parse_cmd_type(input: &[u8]) -> IResult<&[u8], CmdType> {
    let (input, cmd_code) = be_u16(input)?;
    let (input, order) = parse_order(input, cmd_code)?;
    Ok((input, CmdType { cmd_code, order }))
}
