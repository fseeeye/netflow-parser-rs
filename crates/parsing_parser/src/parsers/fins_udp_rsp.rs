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
pub struct FinsUdpRspHeader<'a> {
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

pub fn parse_fins_udp_rsp_header(input: &[u8]) -> IResult<&[u8], FinsUdpRspHeader> {
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
        FinsUdpRspHeader {
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

pub fn parse_fins_udp_rsp_layer<'a>(
    input: &'a [u8],
    link_layer: LinkLayer,
    network_layer: NetworkLayer<'a>,
    transport_layer: TransportLayer<'a>,
    options: &QuinPacketOptions,
) -> QuinPacket<'a> {
    let current_prototype = ProtocolType::Application(ApplicationProtocol::FinsUdpRsp);

    let (input, fins_udp_rsp_header) = match parse_fins_udp_rsp_header(input) {
        Ok(o) => o,
        Err(_e) => {
            return QuinPacket::L4(L4Packet {
                link_layer,
                network_layer,
                transport_layer,
                error: Some(ParseError::ParsingHeader),
                remain: input,
            })
        }
    };

    if Some(current_prototype) == options.stop {
        let application_layer = ApplicationLayer::FinsUdpRsp(fins_udp_rsp_header);
        return QuinPacket::L5(L5Packet {
            link_layer,
            network_layer,
            transport_layer,
            application_layer,
            error: None,
            remain: input,
        });
    };

    let application_layer = ApplicationLayer::FinsUdpRsp(fins_udp_rsp_header);
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
pub enum MultipleMemoryAreaReadItemChoice<'a> {
    MultipleMemoryAreaReadItem1 { item: &'a [u8] },
    MultipleMemoryAreaReadItem2 { item: &'a [u8] },
    MultipleMemoryAreaReadItem4 { item: &'a [u8] },
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MultipleMemoryAreaReadItem<'a> {
    pub memory_area_code: u8,
    pub multiple_memory_area_read_item_choice: MultipleMemoryAreaReadItemChoice<'a>,
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
pub struct ConnectionDataReadDataItem<'a> {
    pub unit_address: u8,
    pub model_number: &'a [u8],
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ErrorLogReadDataItem {
    pub error_reset_fal_1: u16,
    pub error_reset_fal_2: u16,
    pub minute: u8,
    pub second: u8,
    pub day: u8,
    pub hour: u8,
    pub year: u8,
    pub month: u8,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct FileNameReadDiskDataItem<'a> {
    pub volume_label: &'a [u8],
    pub date: u32,
    pub total_capacity: u32,
    pub unused_capacity: u32,
    pub total_number_of_files: u16,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct FileNameReadFileDataItem<'a> {
    pub file_name: &'a [u8],
    pub date: u32,
    pub file_capacity: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct FileMemoryIndexReadDataItem {
    pub data_type: u8,
    pub control_data: u8,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CycleTimeReadChoice {
    CycleTimeRead2 {
        rsp_code: u16,
    },
    CycleTimeRead14 {
        rsp_code: u16,
        averge_cycle_time: u32,
        max_cycle_time: u32,
        min_cycle_time: u32,
    },
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AccessRightAcquireChoice {
    AccessRightAcquire2 {
        rsp_code: u16,
    },
    AccessRightAcquire5 {
        rsp_code: u16,
        unit_address: u8,
        node_number: u8,
        network_address: u8,
    },
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MessageInfo<'a> {
    pub item: &'a [u8],
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MessageReadOrClearOrFALSReadChoice<'a> {
    MessageReadOrClearOrFALSRead20 {
        rsp_code: u16,
        fals: u16,
        error_message: &'a [u8],
    },
    MessageReadOrClearOrFALSRead2 {
        rsp_code: u16,
    },
    MessageReadOrClearOrFALSReadLong {
        rsp_code: u16,
        message_info: u16,
        message: Vec<MessageInfo<'a>>,
    },
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ControllerDataReadDataChoice<'a> {
    ControllerDataReadDataItem161 {
        rsp_code: u16,
        controller_model: &'a [u8],
        controller_version: &'a [u8],
        for_system_use: &'a [u8],
        program_area_size: u16,
        ios_size: u8,
        number_of_dw_words: u16,
        time_counter_size: u8,
        expansion_dm_size: u8,
        number_step_transitions: u16,
        kind_memory_card: u8,
        memory_card_size: u16,
        cpu_bus_unit_0: u16,
        cpu_bus_unit_1: u16,
        cpu_bus_unit_2: u16,
        cpu_bus_unit_3: u16,
        cpu_bus_unit_4: u16,
        cpu_bus_unit_5: u16,
        cpu_bus_unit_6: u16,
        cpu_bus_unit_7: u16,
        cpu_bus_unit_8: u16,
        cpu_bus_unit_9: u16,
        cpu_bus_unit_10: u16,
        cpu_bus_unit_11: u16,
        cpu_bus_unit_12: u16,
        cpu_bus_unit_13: u16,
        cpu_bus_unit_14: u16,
        cpu_bus_unit_15: u16,
        cpu_bus_rsserved: &'a [u8],
        remote_io_data_1: u8,
        remote_io_data_2: u8,
        pc_status: u8,
    },
    ControllerDataReadDataItem94 {
        rsp_code: u16,
        controller_model: &'a [u8],
        controller_version: &'a [u8],
        for_system_use: &'a [u8],
        program_area_size: u16,
        ios_size: u8,
        number_of_dw_words: u16,
        time_counter_size: u8,
        expansion_dm_size: u8,
        number_step_transitions: u16,
        kind_memory_card: u8,
        memory_card_size: u16,
    },
    ControllerDataReadDataItem69 {
        rsp_code: u16,
        cpu_bus_unit_0: u16,
        cpu_bus_unit_1: u16,
        cpu_bus_unit_2: u16,
        cpu_bus_unit_3: u16,
        cpu_bus_unit_4: u16,
        cpu_bus_unit_5: u16,
        cpu_bus_unit_6: u16,
        cpu_bus_unit_7: u16,
        cpu_bus_unit_8: u16,
        cpu_bus_unit_9: u16,
        cpu_bus_unit_10: u16,
        cpu_bus_unit_11: u16,
        cpu_bus_unit_12: u16,
        cpu_bus_unit_13: u16,
        cpu_bus_unit_14: u16,
        cpu_bus_unit_15: u16,
        cpu_bus_rsserved: &'a [u8],
        remote_io_data_1: u8,
        remote_io_data_2: u8,
        pc_status: u8,
    },
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Order<'a> {
    MemoryAreaRead {
        rsp_code: u16,
        last_data: &'a [u8],
    },
    MemoryAreaWrite {
        memory_area_code: u8,
        beginning_address: u16,
        beginning_address_bits: u8,
        number_of_items: u16,
        command_data: u16,
    },
    MemoryAreaFill {
        memory_area_code: u8,
        beginning_address: u16,
        beginning_address_bits: u8,
        number_of_items: u16,
        command_data: u16,
    },
    MultipleMemoryAreaRead {
        rsp_code: u16,
        data: Vec<MultipleMemoryAreaReadItem<'a>>,
    },
    MemoryAreaTransfer {
        rsp_code: u16,
    },
    ParameterAreaRead {
        rsp_code: u16,
        parameter_area_code: u16,
        beginning_word: u16,
        number_words_or_bytes: u16,
        rsp_data: &'a [u8],
    },
    ParameterAreaWrite {
        rsp_code: u16,
    },
    ParameterAreaClear {
        rsp_code: u16,
    },
    DataLinkTableRead {
        rsp_code: u16,
        number_of_link_nodes: u8,
        data: Vec<DLTBLockDataItem>,
    },
    DataLinkTableRWrite {
        rsp_code: u16,
    },
    ParameterAreaProtect {
        rsp_code: u16,
    },
    ParameterAreaProtectClear {
        rsp_code: u16,
    },
    ProgramAreaRead {
        rsp_code: u16,
        program_number: u16,
        beginning_word: u32,
        words_of_bytes: u16,
        rsp_data: &'a [u8],
    },
    ProgramAreaWrite {
        rsp_code: u16,
        program_number: u16,
        beginning_word: u32,
        words_of_bytes: u16,
    },
    ProgramAreaClear {
        rsp_code: u16,
    },
    Run {
        rsp_code: u16,
    },
    Stop {
        rsp_code: u16,
    },
    ControllerDataRead {
        controller_data_read_data_choice: ControllerDataReadDataChoice<'a>,
    },
    ConnectionDataRead {
        rsp_code: u16,
        number_of_units: u8,
        data: Vec<ConnectionDataReadDataItem<'a>>,
    },
    ControllerStatusRead {
        rsp_code: u16,
        status_stop: u8,
        mode_code: u8,
        fatal_error_data: u16,
        non_fatal_error_data: u16,
        message: u16,
        fals: u16,
        error_message: &'a [u8],
    },
    NetworkStatusRead {
        rsp_code: u16,
        network_nodes_status: &'a [u8],
        communications_cycle_time: u16,
        current_polling_unit_node_number: u8,
        cyclic_operation: u8,
        cyclic_transmission_status: u8,
        network_nodes_non_fatal_error_status: &'a [u8],
        network_nodes_cyclic_error_counters: &'a [u8],
    },
    DataLinkStatusRead {
        rsp_code: u16,
        status_flags: u8,
        master_node_number: u8,
        data: &'a [u8],
    },
    CycleTimeRead {
        cycle_time_read_choice: CycleTimeReadChoice,
    },
    ClcokRead {
        rsp_code: u16,
        year: u8,
        month: u8,
        date: u8,
        hour: u8,
        minute: u8,
        second: u8,
        day: u8,
    },
    ClcokWrite {
        rsp_code: u16,
    },
    LoopBackTest {
        rsp_code: u16,
        data: &'a [u8],
    },
    BroadcastTestResultsRead {
        rsp_code: u16,
        number_of_receptions: u16,
    },
    BroadcastTestDataSend {},
    MessageReadClearFALSRead {
        message_read_or_clear_or_fals_read_choice: MessageReadOrClearOrFALSReadChoice<'a>,
    },
    AccessRightAcquire {
        access_right_acquire_choice: AccessRightAcquireChoice,
    },
    AccessRightForcedAcquire {
        rsp_code: u16,
    },
    AccessRightRelease {
        rsp_code: u16,
    },
    ErrorClear {
        rsp_code: u16,
    },
    ErrorLogRead {
        rsp_code: u16,
        max_number_of_stored_records: u16,
        number_of_stored_records: u16,
        number_of_records: u16,
        error_log_data: Vec<ErrorLogReadDataItem>,
    },
    ErrorLogClear {
        rsp_code: u16,
    },
    FileNameRead {
        rsp_code: u16,
        disk_data: FileNameReadDiskDataItem<'a>,
        number_of_files: u16,
        error_log_data: Vec<FileNameReadFileDataItem<'a>>,
    },
    SingleFileRead {
        rsp_code: u16,
        file_capacity: u16,
        file_position: u32,
        data_length: u16,
        file_data: &'a [u8],
    },
    SingleFileWrite {
        rsp_code: u16,
    },
    MemoryCardFormat {
        rsp_code: u16,
    },
    FileDelete {
        rsp_code: u16,
        number_of_files: u16,
    },
    VolumeLabelCreateOrDelete {
        rsp_code: u16,
    },
    FileCopy {
        rsp_code: u16,
    },
    FileNameChange {
        rsp_code: u16,
    },
    FileDataCheck {
        rsp_code: u16,
    },
    MemoryAreaFileTransfer {
        rsp_code: u16,
        number_of_items: u16,
    },
    ParameterAreaFileTransfer {
        rsp_code: u16,
        number_of_word_or_bytes: u16,
    },
    ProgramAreaFileTransfer {},
    FileMemoryIndexRead {
        rsp_code: u16,
        number_of_blocks_remaining: u16,
        total_number_of_blocks: u16,
        omron_type: u8,
        data: Vec<FileMemoryIndexReadDataItem>,
    },
    FileMemoryRead {
        rsp_code: u16,
        data_type: u8,
        control_data: u8,
        data: &'a [u8],
    },
    FileMemoryWrite {
        rsp_code: u16,
    },
    ForcedSetOrReset {
        rsp_code: u16,
    },
    ForcedSetOrResetCancel {
        rsp_code: u16,
    },
    MultipleForcedStatusRead {
        rsp_code: u16,
        memory_area_code: u16,
        beginning_address: u32,
        number_of_units: u16,
        data: &'a [u8],
    },
    NameSet {
        rsp_code: u16,
    },
    NameDelete {
        rsp_code: u16,
    },
    NameRead {},
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CmdType<'a> {
    pub cmd_code: u16,
    pub order: Order<'a>,
}

fn parse_multiple_memory_area_read_item1(
    input: &[u8],
) -> IResult<&[u8], MultipleMemoryAreaReadItemChoice> {
    let (input, item) = take(1 as usize)(input)?;
    Ok((
        input,
        MultipleMemoryAreaReadItemChoice::MultipleMemoryAreaReadItem1 { item },
    ))
}

fn parse_multiple_memory_area_read_item2(
    input: &[u8],
) -> IResult<&[u8], MultipleMemoryAreaReadItemChoice> {
    let (input, item) = take(2 as usize)(input)?;
    Ok((
        input,
        MultipleMemoryAreaReadItemChoice::MultipleMemoryAreaReadItem2 { item },
    ))
}

fn parse_multiple_memory_area_read_item4(
    input: &[u8],
) -> IResult<&[u8], MultipleMemoryAreaReadItemChoice> {
    let (input, item) = take(4 as usize)(input)?;
    Ok((
        input,
        MultipleMemoryAreaReadItemChoice::MultipleMemoryAreaReadItem4 { item },
    ))
}

pub fn parse_multiple_memory_area_read_item_choice(
    input: &[u8],
    memory_area_code: u8,
) -> IResult<&[u8], MultipleMemoryAreaReadItemChoice> {
    let (input, multiple_memory_area_read_item_choice) = match memory_area_code {
        0x00 | 0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x09 | 0x1B | 0x20 | 0x21
        | 0x22 | 0x23 | 0x24 | 0x25 | 0x26 | 0x27 | 0x28 | 0x29 | 0x2A | 0x2B | 0x2C | 0x30
        | 0x31 | 0x32 | 0x33 | 0x40 | 0x41 | 0x43 | 0x44 | 0x46 | 0x49 | 0x70 | 0x71 | 0x72 => {
            parse_multiple_memory_area_read_item1(input)
        }
        0x80 | 0x81 | 0x82 | 0x84 | 0x85 | 0x89 | 0x90 | 0x91 | 0x92 | 0x93 | 0x94 | 0x95
        | 0x96 | 0x97 | 0x98 | 0x9C | 0xA0 | 0xA1 | 0xA2 | 0xA3 | 0xA4 | 0xA5 | 0xA6 | 0xA7
        | 0xA8 | 0xA9 | 0xAA | 0xAB | 0xAC | 0xB0 | 0xB1 | 0xB2 | 0xB3 | 0xBC => {
            parse_multiple_memory_area_read_item2(input)
        }
        0xC0 | 0xDC | 0xDD | 0xF0 | 0xF1 | 0xF2 => parse_multiple_memory_area_read_item4(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, multiple_memory_area_read_item_choice))
}

pub fn parse_multiple_memory_area_read_item(
    input: &[u8],
) -> IResult<&[u8], MultipleMemoryAreaReadItem> {
    let (input, memory_area_code) = u8(input)?;
    let (input, multiple_memory_area_read_item_choice) =
        parse_multiple_memory_area_read_item_choice(input, memory_area_code)?;
    Ok((
        input,
        MultipleMemoryAreaReadItem {
            memory_area_code,
            multiple_memory_area_read_item_choice,
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

pub fn parse_connection_data_read_data_item(
    input: &[u8],
) -> IResult<&[u8], ConnectionDataReadDataItem> {
    let (input, unit_address) = u8(input)?;
    let (input, model_number) = take(20 as usize)(input)?;
    Ok((
        input,
        ConnectionDataReadDataItem {
            unit_address,
            model_number,
        },
    ))
}

pub fn parse_error_log_read_data_item(input: &[u8]) -> IResult<&[u8], ErrorLogReadDataItem> {
    let (input, error_reset_fal_1) = be_u16(input)?;
    let (input, error_reset_fal_2) = be_u16(input)?;
    let (input, minute) = u8(input)?;
    let (input, second) = u8(input)?;
    let (input, day) = u8(input)?;
    let (input, hour) = u8(input)?;
    let (input, year) = u8(input)?;
    let (input, month) = u8(input)?;
    Ok((
        input,
        ErrorLogReadDataItem {
            error_reset_fal_1,
            error_reset_fal_2,
            minute,
            second,
            day,
            hour,
            year,
            month,
        },
    ))
}

pub fn parse_file_name_read_disk_data_item(
    input: &[u8],
) -> IResult<&[u8], FileNameReadDiskDataItem> {
    let (input, volume_label) = take(12 as usize)(input)?;
    let (input, date) = be_u32(input)?;
    let (input, total_capacity) = be_u32(input)?;
    let (input, unused_capacity) = be_u32(input)?;
    let (input, total_number_of_files) = be_u16(input)?;
    Ok((
        input,
        FileNameReadDiskDataItem {
            volume_label,
            date,
            total_capacity,
            unused_capacity,
            total_number_of_files,
        },
    ))
}

pub fn parse_file_name_read_file_data_item(
    input: &[u8],
) -> IResult<&[u8], FileNameReadFileDataItem> {
    let (input, file_name) = take(12 as usize)(input)?;
    let (input, date) = be_u32(input)?;
    let (input, file_capacity) = be_u32(input)?;
    Ok((
        input,
        FileNameReadFileDataItem {
            file_name,
            date,
            file_capacity,
        },
    ))
}

pub fn parse_file_memory_index_read_data_item(
    input: &[u8],
) -> IResult<&[u8], FileMemoryIndexReadDataItem> {
    let (input, data_type) = u8(input)?;
    let (input, control_data) = u8(input)?;
    Ok((
        input,
        FileMemoryIndexReadDataItem {
            data_type,
            control_data,
        },
    ))
}

fn parse_cycle_time_read2(input: &[u8]) -> IResult<&[u8], CycleTimeReadChoice> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, CycleTimeReadChoice::CycleTimeRead2 { rsp_code }))
}

fn parse_cycle_time_read14(input: &[u8]) -> IResult<&[u8], CycleTimeReadChoice> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, averge_cycle_time) = be_u32(input)?;
    let (input, max_cycle_time) = be_u32(input)?;
    let (input, min_cycle_time) = be_u32(input)?;
    Ok((
        input,
        CycleTimeReadChoice::CycleTimeRead14 {
            rsp_code,
            averge_cycle_time,
            max_cycle_time,
            min_cycle_time,
        },
    ))
}

pub fn parse_cycle_time_read_choice(input: &[u8]) -> IResult<&[u8], CycleTimeReadChoice> {
    let (input, cycle_time_read_choice) = match input.len() {
        0x02 => parse_cycle_time_read2(input),
        0x0e => parse_cycle_time_read14(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, cycle_time_read_choice))
}

fn parse_access_right_acquire2(input: &[u8]) -> IResult<&[u8], AccessRightAcquireChoice> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((
        input,
        AccessRightAcquireChoice::AccessRightAcquire2 { rsp_code },
    ))
}

fn parse_access_right_acquire5(input: &[u8]) -> IResult<&[u8], AccessRightAcquireChoice> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, unit_address) = u8(input)?;
    let (input, node_number) = u8(input)?;
    let (input, network_address) = u8(input)?;
    Ok((
        input,
        AccessRightAcquireChoice::AccessRightAcquire5 {
            rsp_code,
            unit_address,
            node_number,
            network_address,
        },
    ))
}

pub fn parse_access_right_acquire_choice(input: &[u8]) -> IResult<&[u8], AccessRightAcquireChoice> {
    let (input, access_right_acquire_choice) = match input.len() {
        0x02 => parse_access_right_acquire2(input),
        0x05 => parse_access_right_acquire5(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, access_right_acquire_choice))
}

pub fn parse_message_info(input: &[u8]) -> IResult<&[u8], MessageInfo> {
    let (input, item) = take(32 as usize)(input)?;
    Ok((input, MessageInfo { item }))
}

fn parse_message_read_or_clear_or_fals_read20(
    input: &[u8],
) -> IResult<&[u8], MessageReadOrClearOrFALSReadChoice> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, fals) = be_u16(input)?;
    let (input, error_message) = take(16 as usize)(input)?;
    Ok((
        input,
        MessageReadOrClearOrFALSReadChoice::MessageReadOrClearOrFALSRead20 {
            rsp_code,
            fals,
            error_message,
        },
    ))
}

fn parse_message_read_or_clear_or_fals_read2(
    input: &[u8],
) -> IResult<&[u8], MessageReadOrClearOrFALSReadChoice> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((
        input,
        MessageReadOrClearOrFALSReadChoice::MessageReadOrClearOrFALSRead2 { rsp_code },
    ))
}

fn parse_message_read_or_clear_or_fals_read_long(
    input: &[u8],
) -> IResult<&[u8], MessageReadOrClearOrFALSReadChoice> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, message_info) = be_u16(input)?;
    let (input, message) = count(
        parse_message_info,
        (input.len() as usize / 32 as usize) as usize,
    )(input)?;
    Ok((
        input,
        MessageReadOrClearOrFALSReadChoice::MessageReadOrClearOrFALSReadLong {
            rsp_code,
            message_info,
            message,
        },
    ))
}

pub fn parse_message_read_or_clear_or_fals_read_choice(
    input: &[u8],
) -> IResult<&[u8], MessageReadOrClearOrFALSReadChoice> {
    let (input, message_read_or_clear_or_fals_read_choice) = match input.len() {
        0x14 => parse_message_read_or_clear_or_fals_read20(input),
        0x02 => parse_message_read_or_clear_or_fals_read2(input),
        _ => parse_message_read_or_clear_or_fals_read_long(input),
    }?;
    Ok((input, message_read_or_clear_or_fals_read_choice))
}

fn parse_controller_data_read_data_item161(
    input: &[u8],
) -> IResult<&[u8], ControllerDataReadDataChoice> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, controller_model) = take(20 as usize)(input)?;
    let (input, controller_version) = take(20 as usize)(input)?;
    let (input, for_system_use) = take(40 as usize)(input)?;
    let (input, program_area_size) = be_u16(input)?;
    let (input, ios_size) = u8(input)?;
    let (input, number_of_dw_words) = be_u16(input)?;
    let (input, time_counter_size) = u8(input)?;
    let (input, expansion_dm_size) = u8(input)?;
    let (input, number_step_transitions) = be_u16(input)?;
    let (input, kind_memory_card) = u8(input)?;
    let (input, memory_card_size) = be_u16(input)?;
    let (input, cpu_bus_unit_0) = be_u16(input)?;
    let (input, cpu_bus_unit_1) = be_u16(input)?;
    let (input, cpu_bus_unit_2) = be_u16(input)?;
    let (input, cpu_bus_unit_3) = be_u16(input)?;
    let (input, cpu_bus_unit_4) = be_u16(input)?;
    let (input, cpu_bus_unit_5) = be_u16(input)?;
    let (input, cpu_bus_unit_6) = be_u16(input)?;
    let (input, cpu_bus_unit_7) = be_u16(input)?;
    let (input, cpu_bus_unit_8) = be_u16(input)?;
    let (input, cpu_bus_unit_9) = be_u16(input)?;
    let (input, cpu_bus_unit_10) = be_u16(input)?;
    let (input, cpu_bus_unit_11) = be_u16(input)?;
    let (input, cpu_bus_unit_12) = be_u16(input)?;
    let (input, cpu_bus_unit_13) = be_u16(input)?;
    let (input, cpu_bus_unit_14) = be_u16(input)?;
    let (input, cpu_bus_unit_15) = be_u16(input)?;
    let (input, cpu_bus_rsserved) = take(32 as usize)(input)?;
    let (input, remote_io_data_1) = u8(input)?;
    let (input, remote_io_data_2) = u8(input)?;
    let (input, pc_status) = u8(input)?;
    Ok((
        input,
        ControllerDataReadDataChoice::ControllerDataReadDataItem161 {
            rsp_code,
            controller_model,
            controller_version,
            for_system_use,
            program_area_size,
            ios_size,
            number_of_dw_words,
            time_counter_size,
            expansion_dm_size,
            number_step_transitions,
            kind_memory_card,
            memory_card_size,
            cpu_bus_unit_0,
            cpu_bus_unit_1,
            cpu_bus_unit_2,
            cpu_bus_unit_3,
            cpu_bus_unit_4,
            cpu_bus_unit_5,
            cpu_bus_unit_6,
            cpu_bus_unit_7,
            cpu_bus_unit_8,
            cpu_bus_unit_9,
            cpu_bus_unit_10,
            cpu_bus_unit_11,
            cpu_bus_unit_12,
            cpu_bus_unit_13,
            cpu_bus_unit_14,
            cpu_bus_unit_15,
            cpu_bus_rsserved,
            remote_io_data_1,
            remote_io_data_2,
            pc_status,
        },
    ))
}

fn parse_controller_data_read_data_item94(
    input: &[u8],
) -> IResult<&[u8], ControllerDataReadDataChoice> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, controller_model) = take(20 as usize)(input)?;
    let (input, controller_version) = take(20 as usize)(input)?;
    let (input, for_system_use) = take(40 as usize)(input)?;
    let (input, program_area_size) = be_u16(input)?;
    let (input, ios_size) = u8(input)?;
    let (input, number_of_dw_words) = be_u16(input)?;
    let (input, time_counter_size) = u8(input)?;
    let (input, expansion_dm_size) = u8(input)?;
    let (input, number_step_transitions) = be_u16(input)?;
    let (input, kind_memory_card) = u8(input)?;
    let (input, memory_card_size) = be_u16(input)?;
    Ok((
        input,
        ControllerDataReadDataChoice::ControllerDataReadDataItem94 {
            rsp_code,
            controller_model,
            controller_version,
            for_system_use,
            program_area_size,
            ios_size,
            number_of_dw_words,
            time_counter_size,
            expansion_dm_size,
            number_step_transitions,
            kind_memory_card,
            memory_card_size,
        },
    ))
}

fn parse_controller_data_read_data_item69(
    input: &[u8],
) -> IResult<&[u8], ControllerDataReadDataChoice> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, cpu_bus_unit_0) = be_u16(input)?;
    let (input, cpu_bus_unit_1) = be_u16(input)?;
    let (input, cpu_bus_unit_2) = be_u16(input)?;
    let (input, cpu_bus_unit_3) = be_u16(input)?;
    let (input, cpu_bus_unit_4) = be_u16(input)?;
    let (input, cpu_bus_unit_5) = be_u16(input)?;
    let (input, cpu_bus_unit_6) = be_u16(input)?;
    let (input, cpu_bus_unit_7) = be_u16(input)?;
    let (input, cpu_bus_unit_8) = be_u16(input)?;
    let (input, cpu_bus_unit_9) = be_u16(input)?;
    let (input, cpu_bus_unit_10) = be_u16(input)?;
    let (input, cpu_bus_unit_11) = be_u16(input)?;
    let (input, cpu_bus_unit_12) = be_u16(input)?;
    let (input, cpu_bus_unit_13) = be_u16(input)?;
    let (input, cpu_bus_unit_14) = be_u16(input)?;
    let (input, cpu_bus_unit_15) = be_u16(input)?;
    let (input, cpu_bus_rsserved) = take(32 as usize)(input)?;
    let (input, remote_io_data_1) = u8(input)?;
    let (input, remote_io_data_2) = u8(input)?;
    let (input, pc_status) = u8(input)?;
    Ok((
        input,
        ControllerDataReadDataChoice::ControllerDataReadDataItem69 {
            rsp_code,
            cpu_bus_unit_0,
            cpu_bus_unit_1,
            cpu_bus_unit_2,
            cpu_bus_unit_3,
            cpu_bus_unit_4,
            cpu_bus_unit_5,
            cpu_bus_unit_6,
            cpu_bus_unit_7,
            cpu_bus_unit_8,
            cpu_bus_unit_9,
            cpu_bus_unit_10,
            cpu_bus_unit_11,
            cpu_bus_unit_12,
            cpu_bus_unit_13,
            cpu_bus_unit_14,
            cpu_bus_unit_15,
            cpu_bus_rsserved,
            remote_io_data_1,
            remote_io_data_2,
            pc_status,
        },
    ))
}

pub fn parse_controller_data_read_data_choice(
    input: &[u8],
) -> IResult<&[u8], ControllerDataReadDataChoice> {
    let (input, controller_data_read_data_choice) = match input.len() {
        0xa1 => parse_controller_data_read_data_item161(input),
        0x5e => parse_controller_data_read_data_item94(input),
        0x45 => parse_controller_data_read_data_item69(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, controller_data_read_data_choice))
}

fn parse_memory_area_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, last_data) = take(input.len() as usize)(input)?;
    Ok((
        input,
        Order::MemoryAreaRead {
            rsp_code,
            last_data,
        },
    ))
}

fn parse_memory_area_write(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, memory_area_code) = u8(input)?;
    let (input, beginning_address) = be_u16(input)?;
    let (input, beginning_address_bits) = u8(input)?;
    let (input, number_of_items) = be_u16(input)?;
    let (input, command_data) = be_u16(input)?;
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
    let (input, rsp_code) = be_u16(input)?;
    let (input, data) = get_data_with_multiple_memory_area_read_item(input)?;
    Ok((input, Order::MultipleMemoryAreaRead { rsp_code, data }))
}

fn get_data_with_multiple_memory_area_read_item(
    input: &[u8],
) -> IResult<&[u8], Vec<MultipleMemoryAreaReadItem>> {
    let mut data = Vec::new();
    let mut _data: MultipleMemoryAreaReadItem;
    let mut input = input;

    while input.len() > 0 {
        (input, _data) = parse_multiple_memory_area_read_item(input)?;
        data.push(_data);
    }

    Ok((input, data))
}

fn parse_memory_area_transfer(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, Order::MemoryAreaTransfer { rsp_code }))
}

fn parse_parameter_area_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, parameter_area_code) = be_u16(input)?;
    let (input, beginning_word) = be_u16(input)?;
    let (input, number_words_or_bytes) = be_u16(input)?;
    let (input, rsp_data) = take(input.len() as usize)(input)?;
    Ok((
        input,
        Order::ParameterAreaRead {
            rsp_code,
            parameter_area_code,
            beginning_word,
            number_words_or_bytes,
            rsp_data,
        },
    ))
}

fn parse_parameter_area_write(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, Order::ParameterAreaWrite { rsp_code }))
}

fn parse_parameter_area_clear(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, Order::ParameterAreaClear { rsp_code }))
}

fn parse_data_link_table_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, number_of_link_nodes) = u8(input)?;
    let (input, data) = get_data_with_dltb_lock_data_item(input)?;
    Ok((
        input,
        Order::DataLinkTableRead {
            rsp_code,
            number_of_link_nodes,
            data,
        },
    ))
}

fn get_data_with_dltb_lock_data_item(input: &[u8]) -> IResult<&[u8], Vec<DLTBLockDataItem>> {
    let mut data = Vec::new();
    let mut _data: DLTBLockDataItem;
    let mut input = input;

    while input.len() > 0 {
        (input, _data) = parse_dltb_lock_data_item(input)?;
        data.push(_data);
    }

    Ok((input, data))
}

fn parse_data_link_table_r_write(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, Order::DataLinkTableRWrite { rsp_code }))
}

fn parse_parameter_area_protect(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, Order::ParameterAreaProtect { rsp_code }))
}

fn parse_parameter_area_protect_clear(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, Order::ParameterAreaProtectClear { rsp_code }))
}

fn parse_program_area_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, program_number) = be_u16(input)?;
    let (input, beginning_word) = be_u32(input)?;
    let (input, words_of_bytes) = be_u16(input)?;
    let (input, rsp_data) = take(input.len() as usize)(input)?;
    Ok((
        input,
        Order::ProgramAreaRead {
            rsp_code,
            program_number,
            beginning_word,
            words_of_bytes,
            rsp_data,
        },
    ))
}

fn parse_program_area_write(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, program_number) = be_u16(input)?;
    let (input, beginning_word) = be_u32(input)?;
    let (input, words_of_bytes) = be_u16(input)?;
    Ok((
        input,
        Order::ProgramAreaWrite {
            rsp_code,
            program_number,
            beginning_word,
            words_of_bytes,
        },
    ))
}

fn parse_program_area_clear(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, Order::ProgramAreaClear { rsp_code }))
}

fn parse_run(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, Order::Run { rsp_code }))
}

fn parse_stop(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, Order::Stop { rsp_code }))
}

fn parse_controller_data_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, controller_data_read_data_choice) = parse_controller_data_read_data_choice(input)?;
    Ok((
        input,
        Order::ControllerDataRead {
            controller_data_read_data_choice,
        },
    ))
}

fn parse_connection_data_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, number_of_units) = u8(input)?;
    let (input, data) = get_data_with_connection_data_read_data_item(input)?;
    Ok((
        input,
        Order::ConnectionDataRead {
            rsp_code,
            number_of_units,
            data,
        },
    ))
}

fn get_data_with_connection_data_read_data_item(
    input: &[u8],
) -> IResult<&[u8], Vec<ConnectionDataReadDataItem>> {
    let mut data = Vec::new();
    let mut _data: ConnectionDataReadDataItem;
    let mut input = input;

    while input.len() > 0 {
        (input, _data) = parse_connection_data_read_data_item(input)?;
        data.push(_data);
    }

    Ok((input, data))
}

fn parse_controller_status_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, status_stop) = u8(input)?;
    let (input, mode_code) = u8(input)?;
    let (input, fatal_error_data) = be_u16(input)?;
    let (input, non_fatal_error_data) = be_u16(input)?;
    let (input, message) = be_u16(input)?;
    let (input, fals) = be_u16(input)?;
    let (input, error_message) = take(input.len() as usize)(input)?;
    Ok((
        input,
        Order::ControllerStatusRead {
            rsp_code,
            status_stop,
            mode_code,
            fatal_error_data,
            non_fatal_error_data,
            message,
            fals,
            error_message,
        },
    ))
}

fn parse_network_status_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, network_nodes_status) = take(31 as usize)(input)?;
    let (input, communications_cycle_time) = be_u16(input)?;
    let (input, current_polling_unit_node_number) = u8(input)?;
    let (input, cyclic_operation) = u8(input)?;
    let (input, cyclic_transmission_status) = u8(input)?;
    let (input, network_nodes_non_fatal_error_status) = take(8 as usize)(input)?;
    let (input, network_nodes_cyclic_error_counters) = take(62 as usize)(input)?;
    Ok((
        input,
        Order::NetworkStatusRead {
            rsp_code,
            network_nodes_status,
            communications_cycle_time,
            current_polling_unit_node_number,
            cyclic_operation,
            cyclic_transmission_status,
            network_nodes_non_fatal_error_status,
            network_nodes_cyclic_error_counters,
        },
    ))
}

fn parse_data_link_status_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, status_flags) = u8(input)?;
    let (input, master_node_number) = u8(input)?;
    let (input, data) = take(input.len() as usize)(input)?;
    Ok((
        input,
        Order::DataLinkStatusRead {
            rsp_code,
            status_flags,
            master_node_number,
            data,
        },
    ))
}

fn parse_cycle_time_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, cycle_time_read_choice) = parse_cycle_time_read_choice(input)?;
    Ok((
        input,
        Order::CycleTimeRead {
            cycle_time_read_choice,
        },
    ))
}

fn parse_clcok_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, year) = u8(input)?;
    let (input, month) = u8(input)?;
    let (input, date) = u8(input)?;
    let (input, hour) = u8(input)?;
    let (input, minute) = u8(input)?;
    let (input, second) = u8(input)?;
    let (input, day) = u8(input)?;
    Ok((
        input,
        Order::ClcokRead {
            rsp_code,
            year,
            month,
            date,
            hour,
            minute,
            second,
            day,
        },
    ))
}

fn parse_clcok_write(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, Order::ClcokWrite { rsp_code }))
}

fn parse_loop_back_test(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, data) = take(input.len() as usize)(input)?;
    Ok((input, Order::LoopBackTest { rsp_code, data }))
}

fn parse_broadcast_test_results_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, number_of_receptions) = be_u16(input)?;
    Ok((
        input,
        Order::BroadcastTestResultsRead {
            rsp_code,
            number_of_receptions,
        },
    ))
}

fn parse_broadcast_test_data_send(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, _) = eof(input)?;
    Ok((input, Order::BroadcastTestDataSend {}))
}

fn parse_message_read_clear_fals_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, message_read_or_clear_or_fals_read_choice) =
        parse_message_read_or_clear_or_fals_read_choice(input)?;
    Ok((
        input,
        Order::MessageReadClearFALSRead {
            message_read_or_clear_or_fals_read_choice,
        },
    ))
}

fn parse_access_right_acquire(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, access_right_acquire_choice) = parse_access_right_acquire_choice(input)?;
    Ok((
        input,
        Order::AccessRightAcquire {
            access_right_acquire_choice,
        },
    ))
}

fn parse_access_right_forced_acquire(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, Order::AccessRightForcedAcquire { rsp_code }))
}

fn parse_access_right_release(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, Order::AccessRightRelease { rsp_code }))
}

fn parse_error_clear(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, Order::ErrorClear { rsp_code }))
}

fn parse_error_log_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, max_number_of_stored_records) = be_u16(input)?;
    let (input, number_of_stored_records) = be_u16(input)?;
    let (input, number_of_records) = be_u16(input)?;
    let (input, error_log_data) = get_error_log_data_with_error_log_read_data_item(input)?;
    Ok((
        input,
        Order::ErrorLogRead {
            rsp_code,
            max_number_of_stored_records,
            number_of_stored_records,
            number_of_records,
            error_log_data,
        },
    ))
}

fn get_error_log_data_with_error_log_read_data_item(
    input: &[u8],
) -> IResult<&[u8], Vec<ErrorLogReadDataItem>> {
    let mut error_log_data = Vec::new();
    let mut _error_log_data: ErrorLogReadDataItem;
    let mut input = input;

    while input.len() > 0 {
        (input, _error_log_data) = parse_error_log_read_data_item(input)?;
        error_log_data.push(_error_log_data);
    }

    Ok((input, error_log_data))
}

fn parse_error_log_clear(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, Order::ErrorLogClear { rsp_code }))
}

fn parse_file_name_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, disk_data) = parse_file_name_read_disk_data_item(input)?;
    let (input, number_of_files) = be_u16(input)?;
    let (input, error_log_data) = get_error_log_data_with_file_name_read_file_data_item(input)?;
    Ok((
        input,
        Order::FileNameRead {
            rsp_code,
            disk_data,
            number_of_files,
            error_log_data,
        },
    ))
}

fn get_error_log_data_with_file_name_read_file_data_item(
    input: &[u8],
) -> IResult<&[u8], Vec<FileNameReadFileDataItem>> {
    let mut error_log_data = Vec::new();
    let mut _error_log_data: FileNameReadFileDataItem;
    let mut input = input;

    while input.len() > 0 {
        (input, _error_log_data) = parse_file_name_read_file_data_item(input)?;
        error_log_data.push(_error_log_data);
    }

    Ok((input, error_log_data))
}

fn parse_single_file_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, file_capacity) = be_u16(input)?;
    let (input, file_position) = be_u32(input)?;
    let (input, data_length) = be_u16(input)?;
    let (input, file_data) = take(input.len() as usize)(input)?;
    Ok((
        input,
        Order::SingleFileRead {
            rsp_code,
            file_capacity,
            file_position,
            data_length,
            file_data,
        },
    ))
}

fn parse_single_file_write(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, Order::SingleFileWrite { rsp_code }))
}

fn parse_memory_card_format(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, Order::MemoryCardFormat { rsp_code }))
}

fn parse_file_delete(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, number_of_files) = be_u16(input)?;
    Ok((
        input,
        Order::FileDelete {
            rsp_code,
            number_of_files,
        },
    ))
}

fn parse_volume_label_create_or_delete(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, Order::VolumeLabelCreateOrDelete { rsp_code }))
}

fn parse_file_copy(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, Order::FileCopy { rsp_code }))
}

fn parse_file_name_change(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, Order::FileNameChange { rsp_code }))
}

fn parse_file_data_check(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, Order::FileDataCheck { rsp_code }))
}

fn parse_memory_area_file_transfer(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, number_of_items) = be_u16(input)?;
    Ok((
        input,
        Order::MemoryAreaFileTransfer {
            rsp_code,
            number_of_items,
        },
    ))
}

fn parse_parameter_area_file_transfer(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, number_of_word_or_bytes) = be_u16(input)?;
    Ok((
        input,
        Order::ParameterAreaFileTransfer {
            rsp_code,
            number_of_word_or_bytes,
        },
    ))
}

fn parse_program_area_file_transfer(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, _) = eof(input)?;
    Ok((input, Order::ProgramAreaFileTransfer {}))
}

fn parse_file_memory_index_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, number_of_blocks_remaining) = be_u16(input)?;
    let (input, total_number_of_blocks) = be_u16(input)?;
    let (input, omron_type) = u8(input)?;
    let (input, data) = get_data_with_file_memory_index_read_data_item(input)?;
    Ok((
        input,
        Order::FileMemoryIndexRead {
            rsp_code,
            number_of_blocks_remaining,
            total_number_of_blocks,
            omron_type,
            data,
        },
    ))
}

fn get_data_with_file_memory_index_read_data_item(
    input: &[u8],
) -> IResult<&[u8], Vec<FileMemoryIndexReadDataItem>> {
    let mut data = Vec::new();
    let mut _data: FileMemoryIndexReadDataItem;
    let mut input = input;

    while input.len() > 0 {
        (input, _data) = parse_file_memory_index_read_data_item(input)?;
        data.push(_data);
    }

    Ok((input, data))
}

fn parse_file_memory_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, data_type) = u8(input)?;
    let (input, control_data) = u8(input)?;
    let (input, data) = take(input.len() as usize)(input)?;
    Ok((
        input,
        Order::FileMemoryRead {
            rsp_code,
            data_type,
            control_data,
            data,
        },
    ))
}

fn parse_file_memory_write(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, Order::FileMemoryWrite { rsp_code }))
}

fn parse_forced_set_or_reset(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, Order::ForcedSetOrReset { rsp_code }))
}

fn parse_forced_set_or_reset_cancel(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, Order::ForcedSetOrResetCancel { rsp_code }))
}

fn parse_multiple_forced_status_read(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    let (input, memory_area_code) = be_u16(input)?;
    let (input, beginning_address) = be_u24(input)?;
    let (input, number_of_units) = be_u16(input)?;
    let (input, data) = take(input.len() as usize)(input)?;
    Ok((
        input,
        Order::MultipleForcedStatusRead {
            rsp_code,
            memory_area_code,
            beginning_address,
            number_of_units,
            data,
        },
    ))
}

fn parse_name_set(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, Order::NameSet { rsp_code }))
}

fn parse_name_delete(input: &[u8]) -> IResult<&[u8], Order> {
    let (input, rsp_code) = be_u16(input)?;
    Ok((input, Order::NameDelete { rsp_code }))
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
        0x0203 => parse_parameter_area_clear(input),
        0x0220 => parse_data_link_table_read(input),
        0x0221 => parse_data_link_table_r_write(input),
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
        0x0602 => parse_network_status_read(input),
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
