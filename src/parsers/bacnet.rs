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
use crate::packet_level::{L1Packet, L2Packet, L3Packet, L4Packet, L5Packet};
#[allow(unused)]
use crate::packet_quin::{QuinPacket, QuinPacketOptions};
#[allow(unused)]
use crate::LayerType;
#[allow(unused)]
use crate::field_type::*;
#[allow(unused)]
use crate::layer_type::*;

#[allow(unused)]
use std::ops::BitAnd;
#[allow(unused)]
use std::ops::BitOr;
#[allow(unused)]
use std::ops::BitXor;


use super::parse_l5_eof_layer;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BacnetHeader<'a> {
    pub bvlc: Bvlc,
    pub npdu: Npdu<'a>,
    pub apdu_option: ApduOption<'a>,
}

pub fn parse_bacnet_header(input: &[u8]) -> IResult<&[u8], BacnetHeader> {
    let (input, bvlc) = parse_bvlc(input)?;
    let (input, npdu) = parse_npdu(input)?;
    let (input, apdu_option) = parse_apdu_option(input, &npdu)?;
    Ok((
        input,
        BacnetHeader {
            bvlc,
            npdu,
            apdu_option
        }
    ))
}

pub(crate) fn parse_bacnet_layer<'a>(input: &'a [u8], link_layer: LinkLayer, network_layer: NetworkLayer<'a>, transport_layer: TransportLayer<'a>, options: &QuinPacketOptions) -> QuinPacket<'a> {
    let current_layertype = LayerType::Application(ApplicationLayerType::Bacnet);

    let (input, bacnet_header) = match parse_bacnet_header(input) {
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
        let application_layer = ApplicationLayer::Bacnet(bacnet_header);
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

    let application_layer = ApplicationLayer::Bacnet(bacnet_header);
    return parse_l5_eof_layer(input, link_layer, network_layer, transport_layer, application_layer, options);
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Bdt {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub mask: Ipv4Addr,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Fdt {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub ttl: u16,
    pub timeout: u16,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BvlcFunctionIpv4Info {
    BvlcResult {
         result_ipv4: u16,
    },
    WriteBroadcastDistributionTable {
         bdt_table: Vec<Bdt>,
    },
    ReadBroadcastDistributionTable {},
    ReadBroadcastDistributionTableAck {
         bdt_table: Vec<Bdt>,
    },
    ForwardedNpdu {
         fwd_ip: Ipv4Addr,
         fwd_port: u16,
    },
    RegisterForeignDevice {
         reg_ttl: u16,
    },
    ReadForeignDeviceTable {},
    ReadForeignDeviceTableAck {
         fdt_table: Vec<Fdt>,
    },
    DeleteForeignDeviceTableEntry {
         fdt_ip: Ipv4Addr,
         fdt_port: u16,
    },
    DistributeBroadcastToNetwork {},
    OriginalUnicastNpdu {},
    OriginalBroadcastNpdu {}
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BvlcFunctionIpv6Info {
    BvlcResult {
         result_ip6: u16,
    },
    OriginalUnicastNpdu {
         virt_dest: u32,
    },
    OriginalBroadcastNpdu {},
    AddressResolution {
         virt_dest: u32,
    },
    ForwardedAddressResolution {
         virt_dest: u32,
         orig_source_addr: Ipv6Addr,
         orig_source_port: u16,
    },
    AddressResolutionAck {
         virt_dest: u32,
    },
    VirtualAddressResolution {},
    VirtualAddressResolutionAck {
         virt_dest: u32,
    },
    ForwardedNpdu {
         orig_source_addr: Ipv6Addr,
         orig_source_port: u16,
    },
    RegisterForeignDevice {
         reg_ttl: u16,
    },
    DeleteForeignDeviceTableEntry {
         fdt_addr: Ipv6Addr,
         fdt_port: u16,
    },
    DistributeBroadcastToNetwork {}
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BvlcTypeInfo {
    Ipv4AnnexJ {
         bvlc_function: u8,
         packet_length: u16,
         bvlc_function_ipv4_info: BvlcFunctionIpv4Info,
    },
    Ipv6AnnexU {
         bvlc_function: u8,
         packet_length: u16,
         bvlc_function_ipv6_info: BvlcFunctionIpv6Info,
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Bvlc {
    pub bvlc_type: u8,
    pub bvlc_type_info: BvlcTypeInfo,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DestAdrEnum {
    Broadcast {},
    ArcnetMac {
         dadr_mstp: u8,
    },
    OtherMac2 {
         dadr_tmp: u16,
    },
    OtherMac3 {
         dadr_tmp: u32,
    },
    OtherMac4 {
         dadr_tmp: u32,
    },
    OtherMac5 {
         dadr_tmp: [u8; 5],
    },
    EthernetMac {
         dadr_eth: MacAddress,
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BacControlDest {
    DestinationSpec {
         dnet: u16,
         dlen: u8,
         dest_adr_enum: DestAdrEnum,
    },
    NonDestinationSpec {}
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BacControlDestExtra {
    DestinationSpec {
         hop_count: u8,
    },
    NonDestinationSpec {}
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SrcAdrEnum {
    ArcnetMac {
         sadr_mstp: u8,
    },
    OtherMac2 {
         sadr_tmp: u16,
    },
    OtherMac3 {
         sadr_tmp: u32,
    },
    OtherMac4 {
         sadr_tmp: u32,
    },
    OtherMac5 {
         sadr_tmp: [u8; 5],
    },
    EthernetMac {
         sadr_eth: MacAddress,
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BacControlSrc {
    SourceSpec {
         snet: u16,
         slen: u8,
         src_adr_enum: SrcAdrEnum,
    },
    NonSourceSpec {}
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RtabItem<'a> {
    pub dnet: u16,
    pub port_id: u8,
    pub info_len: u8,
    pub info: &'a [u8],
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum NsduInfo<'a> {
    IcbR {
         dnet: u16,
         perf: u8,
    },
    Rej {
         reject_reason: u8,
         dnet: u16,
    },
    RBusy {
         dnet_vec: Vec<u16>,
    },
    WhoR {
         dnet_vec: Vec<u16>,
    },
    RAva {
         dnet_vec: Vec<u16>,
    },
    IamR {
         dnet_vec: Vec<u16>,
    },
    InitRtab {
         ports_num: u8,
         rtab_items: Vec<RtabItem<'a>>,
    },
    InitRtabAck {
         ports_num: u8,
         rtab_items: Vec<RtabItem<'a>>,
    },
    EstCon {
         dnet: u16,
         term_time_value: u8,
    },
    DiscCon {
         dnet: u16,
    },
    WhatNetnr {},
    NetnrIs {
         dnet: u16,
         netno_status: u8,
    },
    Vendor {
         vendor_id: u16,
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BacControlNet<'a> {
    NsduContain {
         mesg_type: u8,
         nsdu_info: NsduInfo<'a>,
    },
    NonNsduContain {}
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Npdu<'a> {
    pub version: u8,
    pub control: u8,
    pub bac_control_dest: BacControlDest,
    pub bac_control_src: BacControlSrc,
    pub bac_control_dest_extra: BacControlDestExtra,
    pub bac_control_net: BacControlNet<'a>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SegmentedReqInfo {
    SegmentedReq {
         sequence_number: u8,
         window_size: u8,
    },
    UnsegmentedReq {}
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BacnetObjectPropertyReferenceInfo {
    ObjectIdentifier {
         object_type: u16,
         instance_number: u32,
    },
    PropertyIdentifier {
         property_identifier: u32,
    },
    PropertyArrayIndex {
         property_array_index: u32,
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BacnetObjectPropertyReferenceItem {
    pub context_tag_number: u8,
    pub tag_class: u8,
    pub length_value_type: u8,
    pub bacnet_object_property_reference_info: BacnetObjectPropertyReferenceInfo,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ConfirmedServiceRequest {
    AcknowledgeAlarm {
        
    },
    ConfirmedCovNotification {
        
    },
    ConfirmedEventNotification {
        
    },
    ConfirmedGetAlarmSummary {
        
    },
    GetEnrollmentSummary {
        
    },
    SubscribeCov {
        
    },
    AtomicReadFile {
        
    },
    AtomicWriteFile {
        
    },
    AddListElement {
        
    },
    RemoveListElement {
        
    },
    CreateObject {
        
    },
    DeleteObject {
        
    },
    ReadProperty {
         property_items: Vec<BacnetObjectPropertyReferenceItem>,
    },
    ReadPropertyConditional {
        
    },
    ReadPropertyMultiple {
        
    },
    WriteProperty {
        
    },
    WritePropertyMultiple {
        
    },
    DeviceCommunicationControl {
        
    },
    ConfirmedPrivateTransfer {
        
    },
    ConfirmedTextMessage {
        
    },
    ReinitializeDevice {
        
    },
    VtOpen {
        
    },
    VtClose {
        
    },
    VtData {
        
    },
    Authenticate {
        
    },
    RequestKey {
        
    },
    ReadRange {
        
    },
    LifeSafetyOperation {
        
    },
    SubscribeCovProperty {
        
    },
    GetEventInformation {
        
    },
    SubscribeCovPropertyMultiple {
        
    },
    ConfirmedCovNotificationMultiple {
        
    },
    ConfirmedAuditNotification {
        
    },
    AuditLogQuery {
        
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BacnetObjectPropertyReferenceAckInfo {
    ObjectIdentifier {
         object_type: u16,
         instance_number: u32,
    },
    PropertyIdentifier {
         property_identifier: u32,
    },
    PropertyArrayIndex {
         property_array_index: u32,
    },
    PropertyValueOpen {
         app_context_tag_number: u8,
         app_tag_class: u8,
         app_length_value_type: u8,
         object_type: u16,
         instance_number: u32,
    },
    PropertyValueClose {}
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BacnetObjectPropertyReferenceAckItem {
    pub context_tag_number: u8,
    pub tag_class: u8,
    pub length_value_type: u8,
    pub bacnet_object_property_reference_ack_info: BacnetObjectPropertyReferenceAckInfo,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ConfirmedServiceAck {
    ConfirmedEventNotificationAck {
        
    },
    GetEnrollmentSummaryAck {
        
    },
    AtomicReadFile {
        
    },
    AtomicReadFileAck {
        
    },
    CreateObject {
        
    },
    ReadPropertyAck {
         property_items: Vec<BacnetObjectPropertyReferenceAckItem>,
    },
    ReadPropertyConditionalAck {
        
    },
    ReadPropertyMultipleAck {
        
    },
    ConfirmedPrivateTransferAck {
        
    },
    VtOpenAck {
        
    },
    VtDataAck {
        
    },
    AuthenticateAck {
        
    },
    ReadRangeAck {
        
    },
    GetEventInformationACK {
        
    },
    AuditLogQueryAck {
        
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ApduInfo {
    ComfirmedServiceRequest {
         unknow_bit: u8,
         response_segments: u8,
         max_adpu_size: u8,
         invoke_id: u8,
         segmented_req_info: SegmentedReqInfo,
         service_choice: u8,
         confirmed_service_request: ConfirmedServiceRequest,
    },
    ComplexAckPdu {
         invoke_id: u8,
         segmented_req_info: SegmentedReqInfo,
         service_choice: u8,
         confirmed_service_ack: ConfirmedServiceAck,
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ApduOption<'a> {
    UnknowApdu {
         unknow_data: &'a [u8],
    },
    Apdu {
         apdu_type: u8,
         pdu_flags: u8,
         apdu_info: ApduInfo,
    }
}

pub fn parse_bdt(input: &[u8]) -> IResult<&[u8], Bdt> {
    let (input, ip) = address4(input)?;
    let (input, port) = be_u16(input)?;
    let (input, mask) = address4(input)?;
    Ok((
        input,
        Bdt {
            ip,
            port,
            mask
        }
    ))
}

pub fn parse_fdt(input: &[u8]) -> IResult<&[u8], Fdt> {
    let (input, ip) = address4(input)?;
    let (input, port) = be_u16(input)?;
    let (input, ttl) = be_u16(input)?;
    let (input, timeout) = be_u16(input)?;
    Ok((
        input,
        Fdt {
            ip,
            port,
            ttl,
            timeout
        }
    ))
}

fn get_bdt_table_with_bdt(input: &[u8]) -> IResult<&[u8], Vec<Bdt>> {
    let mut bdt_table = Vec::new();
    let mut _bdt_table: Bdt;
    let mut input = input;

    while input.len() > 0 {
        (input, _bdt_table) = parse_bdt(input)?;
        bdt_table.push(_bdt_table);
    }

    Ok((
        input,
        bdt_table
    ))
}

fn get_fdt_table_with_fdt(input: &[u8]) -> IResult<&[u8], Vec<Fdt>> {
    let mut fdt_table = Vec::new();
    let mut _fdt_table: Fdt;
    let mut input = input;

    while input.len() > 0 {
        (input, _fdt_table) = parse_fdt(input)?;
        fdt_table.push(_fdt_table);
    }

    Ok((
        input,
        fdt_table
    ))
}

pub fn parse_bvlc_function_ipv4_info(input: &[u8], bvlc_function: u8) -> IResult<&[u8], BvlcFunctionIpv4Info> {
    let (input, bvlc_function_ipv4_info) = match bvlc_function {
        0x0 => {
            let (input, result_ipv4) = be_u16(input)?;
            Ok((
                input,
                BvlcFunctionIpv4Info::BvlcResult {
                    result_ipv4
                }
            ))
        }
        0x01 => {
            let (input, bdt_table) = get_bdt_table_with_bdt(input)?;
            Ok((
                input,
                BvlcFunctionIpv4Info::WriteBroadcastDistributionTable {
                    bdt_table
                }
            ))
        }
        0x02 => {
            Ok((
                input,
                BvlcFunctionIpv4Info::ReadBroadcastDistributionTable {}
            ))
        }
        0x03 => {
            let (input, bdt_table) = get_bdt_table_with_bdt(input)?;
            Ok((
                input,
                BvlcFunctionIpv4Info::ReadBroadcastDistributionTableAck {
                    bdt_table
                }
            ))
        }
        0x04 => {
            let (input, fwd_ip) = address4(input)?;
            let (input, fwd_port) = be_u16(input)?;
            Ok((
                input,
                BvlcFunctionIpv4Info::ForwardedNpdu {
                    fwd_ip,
                    fwd_port
                }
            ))
        }
        0x05 => {
            let (input, reg_ttl) = be_u16(input)?;
            Ok((
                input,
                BvlcFunctionIpv4Info::RegisterForeignDevice {
                    reg_ttl
                }
            ))
        }
        0x06 => {
            Ok((
                input,
                BvlcFunctionIpv4Info::ReadForeignDeviceTable {}
            ))
        }
        0x07 => {
            let (input, fdt_table) = get_fdt_table_with_fdt(input)?;
            Ok((
                input,
                BvlcFunctionIpv4Info::ReadForeignDeviceTableAck {
                    fdt_table
                }
            ))
        }
        0x08 => {
            let (input, fdt_ip) = address4(input)?;
            let (input, fdt_port) = be_u16(input)?;
            Ok((
                input,
                BvlcFunctionIpv4Info::DeleteForeignDeviceTableEntry {
                    fdt_ip,
                    fdt_port
                }
            ))
        }
        0x09 => {
            Ok((
                input,
                BvlcFunctionIpv4Info::DistributeBroadcastToNetwork {}
            ))
        }
        0x0a => {
            Ok((
                input,
                BvlcFunctionIpv4Info::OriginalUnicastNpdu {}
            ))
        }
        0x0b => {
            Ok((
                input,
                BvlcFunctionIpv4Info::OriginalBroadcastNpdu {}
            ))
        }
        _ =>  Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }?;
    Ok((input, bvlc_function_ipv4_info))
}



pub fn parse_bvlc_function_ipv6_info(input: &[u8], bvlc_function: u8) -> IResult<&[u8], BvlcFunctionIpv6Info> {
    let (input, bvlc_function_ipv6_info) = match bvlc_function {
        0x0 => {
            let (input, result_ip6) = be_u16(input)?;
            Ok((
                input,
                BvlcFunctionIpv6Info::BvlcResult {
                    result_ip6
                }
            ))
        }
        0x01 => {
            let (input, virt_dest) = be_u24(input)?;
            Ok((
                input,
                BvlcFunctionIpv6Info::OriginalUnicastNpdu {
                    virt_dest
                }
            ))
        }
        0x02 => {
            Ok((
                input,
                BvlcFunctionIpv6Info::OriginalBroadcastNpdu {}
            ))
        }
        0x03 => {
            let (input, virt_dest) = be_u24(input)?;
            Ok((
                input,
                BvlcFunctionIpv6Info::AddressResolution {
                    virt_dest
                }
            ))
        }
        0x04 => {
            let (input, virt_dest) = be_u24(input)?;
            let (input, orig_source_addr) = address6(input)?;
            let (input, orig_source_port) = be_u16(input)?;
            Ok((
                input,
                BvlcFunctionIpv6Info::ForwardedAddressResolution {
                    virt_dest,
                    orig_source_addr,
                    orig_source_port
                }
            ))
        }
        0x05 => {
            let (input, virt_dest) = be_u24(input)?;
            Ok((
                input,
                BvlcFunctionIpv6Info::AddressResolutionAck {
                    virt_dest
                }
            ))
        }
        0x06 => {
            Ok((
                input,
                BvlcFunctionIpv6Info::VirtualAddressResolution {}
            ))
        }
        0x07 => {
            let (input, virt_dest) = be_u24(input)?;
            Ok((
                input,
                BvlcFunctionIpv6Info::VirtualAddressResolutionAck {
                    virt_dest
                }
            ))
        }
        0x08 => {
            let (input, orig_source_addr) = address6(input)?;
            let (input, orig_source_port) = be_u16(input)?;
            Ok((
                input,
                BvlcFunctionIpv6Info::ForwardedNpdu {
                    orig_source_addr,
                    orig_source_port
                }
            ))
        }
        0x09 => {
            let (input, reg_ttl) = be_u16(input)?;
            Ok((
                input,
                BvlcFunctionIpv6Info::RegisterForeignDevice {
                    reg_ttl
                }
            ))
        }
        0x0a => {
            let (input, fdt_addr) = address6(input)?;
            let (input, fdt_port) = be_u16(input)?;
            Ok((
                input,
                BvlcFunctionIpv6Info::DeleteForeignDeviceTableEntry {
                    fdt_addr,
                    fdt_port
                }
            ))
        }
        0x0c => {
            Ok((
                input,
                BvlcFunctionIpv6Info::DistributeBroadcastToNetwork {}
            ))
        }
        _ =>  Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }?;
    Ok((input, bvlc_function_ipv6_info))
}



pub fn parse_bvlc_type_info(input: &[u8], bvlc_type: u8) -> IResult<&[u8], BvlcTypeInfo> {
    let (input, bvlc_type_info) = match bvlc_type {
        0x81 => {
            let (input, bvlc_function) = u8(input)?;
            let (input, packet_length) = be_u16(input)?;
            let bvlc_length: u16;
            if bvlc_function >= 0x09 {
                bvlc_length = 4;
            } else if bvlc_function == 0x04 {
                bvlc_length = 10;
            } else {
                bvlc_length = packet_length;
            }
            if (bvlc_length < 4) || (bvlc_length > packet_length) {
                return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
            }
            let (input, bvlc_function_ipv4_info) = parse_bvlc_function_ipv4_info(input, bvlc_function)?;
            Ok((
                input,
                BvlcTypeInfo::Ipv4AnnexJ {
                    bvlc_function,
                    packet_length,
                    bvlc_function_ipv4_info
                }
            ))
        }
        0x82 => {
            let (input, bvlc_function) = u8(input)?;
            let (input, packet_length) = be_u16(input)?;
            let bvlc_length: u16;
            if (bvlc_function == 0x00) || (bvlc_function == 0x09) {
                bvlc_length = 9;
            } else if (bvlc_function == 0x01) || (bvlc_function == 0x03) || (bvlc_function == 0x05) || (bvlc_function == 0x07) {
                bvlc_length = 10;
            } else if (bvlc_function == 0x02) || (bvlc_function == 0x06) || (bvlc_function == 0x0c) {
                bvlc_length = 7;
            } else if bvlc_function == 0x04 {
                bvlc_length = 28;
            } else if (bvlc_function == 0x08) || (bvlc_function == 0x0a) {
                bvlc_length = 25;
            } else if bvlc_function == 0x0b {
                bvlc_length = 4;
            } else {
                bvlc_length = packet_length;
            }
            if bvlc_length > packet_length {
                return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
            }
            let (input, bvlc_function_ipv6_info) = parse_bvlc_function_ipv6_info(input, bvlc_function)?;
            Ok((
                input,
                BvlcTypeInfo::Ipv6AnnexU {
                    bvlc_function,
                    packet_length,
                    bvlc_function_ipv6_info
                }
            ))
        }
        _ =>  Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }?;
    Ok((input, bvlc_type_info))
}

pub fn parse_bvlc(input: &[u8]) -> IResult<&[u8], Bvlc> {
    let (input, bvlc_type) = u8(input)?;
    let (input, bvlc_type_info) = parse_bvlc_type_info(input, bvlc_type)?;
    Ok((
        input,
        Bvlc {
            bvlc_type,
            bvlc_type_info
        }
    ))
}



pub fn parse_dest_adr_enum(input: &[u8], dlen: u8) -> IResult<&[u8], DestAdrEnum> {
    let (input, dest_adr_enum) = match dlen {
        0x0 => {
            Ok((
                input,
                DestAdrEnum::Broadcast {}
            ))
        }
        0x01 => {
            let (input, dadr_mstp) = u8(input)?;
            Ok((
                input,
                DestAdrEnum::ArcnetMac {
                    dadr_mstp
                }
            ))
        }
        0x02 => {
            let (input, dadr_tmp) = be_u16(input)?;
            Ok((
                input,
                DestAdrEnum::OtherMac2 {
                    dadr_tmp
                }
            ))
        }
        0x03 => {
            let (input, dadr_tmp) = be_u24(input)?;
            Ok((
                input,
                DestAdrEnum::OtherMac3 {
                    dadr_tmp
                }
            ))
        }
        0x04 => {
            let (input, dadr_tmp) = be_u32(input)?;
            Ok((
                input,
                DestAdrEnum::OtherMac4 {
                    dadr_tmp
                }
            ))
        }
        0x05 => {
            let (input, dadr_tmp) = slice_u8_5(input)?;
            Ok((
                input,
                DestAdrEnum::OtherMac5 {
                    dadr_tmp
                }
            ))
        }
        0x06 => {
            let (input, dadr_eth) = mac_address(input)?;
            Ok((
                input,
                DestAdrEnum::EthernetMac {
                    dadr_eth
                }
            ))
        }
        _ =>  Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }?;
    Ok((input, dest_adr_enum))
}



pub fn parse_bac_control_dest(input: &[u8], control: u8) -> IResult<&[u8], BacControlDest> {
    if control & 0x20 == 0x20 {
        let (input, dnet) = be_u16(input)?;
        let (input, dlen) = u8(input)?;
        let (input, dest_adr_enum) = parse_dest_adr_enum(input, dlen)?;
        Ok((
            input,
            BacControlDest::DestinationSpec {
                dnet,
                dlen,
                dest_adr_enum
            }
        ))
    }
    else {
        Ok((
            input,
            BacControlDest::NonDestinationSpec {}
        ))
    }
}



pub fn parse_bac_control_dest_extra(input: &[u8], control: u8) -> IResult<&[u8], BacControlDestExtra> {
    if control & 0x20 == 0x20 {
        let (input, hop_count) = u8(input)?;
        Ok((
            input,
            BacControlDestExtra::DestinationSpec {
                hop_count
            }
        ))
    }
    else {
        Ok((
            input,
            BacControlDestExtra::NonDestinationSpec {}
        ))
    }
}



pub fn parse_src_adr_enum(input: &[u8], slen: u8) -> IResult<&[u8], SrcAdrEnum> {
    let (input, src_adr_enum) = match slen {
        0x01 => {
            let (input, sadr_mstp) = u8(input)?;
            Ok((
                input,
                SrcAdrEnum::ArcnetMac {
                    sadr_mstp
                }
            ))
        }
        0x02 => {
            let (input, sadr_tmp) = be_u16(input)?;
            Ok((
                input,
                SrcAdrEnum::OtherMac2 {
                    sadr_tmp
                }
            ))
        }
        0x03 => {
            let (input, sadr_tmp) = be_u24(input)?;
            Ok((
                input,
                SrcAdrEnum::OtherMac3 {
                    sadr_tmp
                }
            ))
        }
        0x04 => {
            let (input, sadr_tmp) = be_u32(input)?;
            Ok((
                input,
                SrcAdrEnum::OtherMac4 {
                    sadr_tmp
                }
            ))
        }
        0x05 => {
            let (input, sadr_tmp) = slice_u8_5(input)?;
            Ok((
                input,
                SrcAdrEnum::OtherMac5 {
                    sadr_tmp
                }
            ))
        }
        0x06 => {
            let (input, sadr_eth) = mac_address(input)?;
            Ok((
                input,
                SrcAdrEnum::EthernetMac {
                    sadr_eth
                }
            ))
        }
        _ =>  Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }?;
    Ok((input, src_adr_enum))
}



pub fn parse_bac_control_src(input: &[u8], control: u8) -> IResult<&[u8], BacControlSrc> {
    if control & 0x08 == 0x08 {
        let (input, snet) = be_u16(input)?;
        let (input, slen) = u8(input)?;
        let (input, src_adr_enum) = parse_src_adr_enum(input, slen)?;
        Ok((
            input,
            BacControlSrc::SourceSpec {
                snet,
                slen,
                src_adr_enum
            }
        ))
    }
    else {
        Ok((
            input,
            BacControlSrc::NonSourceSpec {}
        ))
    }
}

pub fn parse_rtab_item(input: &[u8]) -> IResult<&[u8], RtabItem> {
    let (input, dnet) = be_u16(input)?;
    let (input, port_id) = u8(input)?;
    let (input, info_len) = u8(input)?;
    let (input, info) = take(info_len as usize)(input)?;
    Ok((
        input,
        RtabItem {
            dnet,
            port_id,
            info_len,
            info
        }
    ))
}

fn get_dnet_vec_with_u16(input: &[u8]) -> IResult<&[u8], Vec<u16>> {
    let mut dnet_vec = Vec::new();
    let mut _dnet_vec: u16;
    let mut input = input;

    while input.len() > 0 {
        (input, _dnet_vec) = be_u16(input)?;
        dnet_vec.push(_dnet_vec);
    }

    Ok((
        input,
        dnet_vec
    ))
}

fn get_rtab_items_with_rtab_item(input: &[u8], ports_num : u8) -> IResult<&[u8], Vec<RtabItem>> {
    let mut rtab_items = Vec::new();
    let mut _rtab_items: RtabItem;
    let mut input = input;
    let len_flag = input.len() - ports_num as usize;

    while input.len() > len_flag {
        (input, _rtab_items) = parse_rtab_item(input)?;
        rtab_items.push(_rtab_items);
    }

    Ok((
        input,
        rtab_items
    ))
}

pub fn parse_nsdu_info(input: &[u8], mesg_type: u8) -> IResult<&[u8], NsduInfo> {
    let (input, nsdu_info) = match mesg_type {
        0x02 => {
            let (input, dnet) = be_u16(input)?;
            let (input, perf) = u8(input)?;
            Ok((
                input,
                NsduInfo::IcbR {
                    dnet,
                    perf
                }
            ))
        }
        0x03 => {
            let (input, reject_reason) = u8(input)?;
            let (input, dnet) = be_u16(input)?;
            Ok((
                input,
                NsduInfo::Rej {
                    reject_reason,
                    dnet
                }
            ))
        }
        0x04 => {
            let (input, dnet_vec) = get_dnet_vec_with_u16(input)?;
            Ok((
                input,
                NsduInfo::RBusy {
                    dnet_vec
                }
            ))
        }
        0x0 => {
            let (input, dnet_vec) = get_dnet_vec_with_u16(input)?;
            Ok((
                input,
                NsduInfo::WhoR {
                    dnet_vec
                }
            ))
        }
        0x05 => {
            let (input, dnet_vec) = get_dnet_vec_with_u16(input)?;
            Ok((
                input,
                NsduInfo::RAva {
                    dnet_vec
                }
            ))
        }
        0x01 => {
            let (input, dnet_vec) = get_dnet_vec_with_u16(input)?;
            Ok((
                input,
                NsduInfo::IamR {
                    dnet_vec
                }
            ))
        }
        0x06 => {
            let (input, ports_num) = u8(input)?;
            let (input, rtab_items) = get_rtab_items_with_rtab_item(input, ports_num)?;
            Ok((
                input,
                NsduInfo::InitRtab {
                    ports_num,
                    rtab_items
                }
            ))
        }
        0x07 => {
            let (input, ports_num) = u8(input)?;
            let (input, rtab_items) = get_rtab_items_with_rtab_item(input, ports_num)?;
            Ok((
                input,
                NsduInfo::InitRtabAck {
                    ports_num,
                    rtab_items
                }
            ))
        }
        0x08 => {
            let (input, dnet) = be_u16(input)?;
            let (input, term_time_value) = u8(input)?;
            Ok((
                input,
                NsduInfo::EstCon {
                    dnet,
                    term_time_value
                }
            ))
        }
        0x09 => {
            let (input, dnet) = be_u16(input)?;
            Ok((
                input,
                NsduInfo::DiscCon {
                    dnet
                }
            ))
        }
        0x12 => {
            Ok((
                input,
                NsduInfo::WhatNetnr {}
            ))
        }
        0x13 => {
            let (input, dnet) = be_u16(input)?;
            let (input, netno_status) = u8(input)?;
            Ok((
                input,
                NsduInfo::NetnrIs {
                    dnet,
                    netno_status
                }
            ))
        }
        0x80 | 0x81 | 0x82 | 0x83 | 0x84 | 0x85 | 0x86 | 0x87 | 0x88 | 0x89 | 0x8a | 0x8b | 0x8c | 0x8d | 0x8e | 0x8f => {
            let (input, vendor_id) = be_u16(input)?;
            Ok((
                input,
                NsduInfo::Vendor {
                    vendor_id
                }
            ))
        }
        _ =>  Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }?;
    Ok((input, nsdu_info))
}



pub fn parse_bac_control_net(input: &[u8], control: u8) -> IResult<&[u8], BacControlNet> {
    if control & 0x80 == 0x80 {
        let (input, mesg_type) = u8(input)?;
        let (input, nsdu_info) = parse_nsdu_info(input, mesg_type)?;
        Ok((
            input,
            BacControlNet::NsduContain {
                mesg_type,
                nsdu_info
            }
        ))
    }
    else {
        Ok((
            input,
            BacControlNet::NonNsduContain {}
        ))
    }
}

pub fn parse_npdu(input: &[u8]) -> IResult<&[u8], Npdu> {
    let (input, version) = u8(input)?;
    let (input, control) = u8(input)?;
    let (input, bac_control_dest) = parse_bac_control_dest(input, control)?;
    let (input, bac_control_src) = parse_bac_control_src(input, control)?;
    let (input, bac_control_dest_extra) = parse_bac_control_dest_extra(input, control)?;
    let (input, bac_control_net) = parse_bac_control_net(input, control)?;
    Ok((
        input,
        Npdu {
            version,
            control,
            bac_control_dest,
            bac_control_src,
            bac_control_dest_extra,
            bac_control_net
        }
    ))
}



pub fn parse_segmented_req_info(input: &[u8], pdu_flags: u8) -> IResult<&[u8], SegmentedReqInfo> {
    let (input, segmented_req_info) = match pdu_flags & 0x08 {
        0x08 => {
            let (input, sequence_number) = u8(input)?;
            let (input, window_size) = u8(input)?;
            Ok((
                input,
                SegmentedReqInfo::SegmentedReq {
                    sequence_number,
                    window_size
                }
            ))
        }
        0x0 => {
            Ok((
                input,
                SegmentedReqInfo::UnsegmentedReq {}
            ))
        }
        _ =>  Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }?;
    Ok((input, segmented_req_info))
}



pub fn parse_bacnet_object_property_reference_info(input: &[u8], context_tag_number: u8, length_value_type: u8) -> IResult<&[u8], BacnetObjectPropertyReferenceInfo> {
    if context_tag_number == 0 {
        let (input, (object_type, instance_number)) = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
            tuple((take_bits(10usize), take_bits(22usize)))
        )(input)?;
        Ok((
            input,
            BacnetObjectPropertyReferenceInfo::ObjectIdentifier {
                object_type, instance_number
            }
        ))
    }
    else if context_tag_number == 1 {
        let (input, property_identifier) = match take_bits::<_, _, _, nom::error::Error<(&[u8], usize)>>((length_value_type * 8) as usize)((input, 0 as usize)) {
            Ok(((input_remain, _offset), rst)) => (input_remain, rst),
            Err(_e) => return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Fail
            )))
        };
        Ok((
            input,
            BacnetObjectPropertyReferenceInfo::PropertyIdentifier {
                property_identifier
            }
        ))
    }
    else if context_tag_number == 2 {
        let (input, property_array_index) = match take_bits::<_, _, _, nom::error::Error<(&[u8], usize)>>((length_value_type * 8) as usize)((input, 0 as usize)) {
            Ok(((input_remain, _offset), rst)) => (input_remain, rst),
            Err(_e) => return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Fail
            )))
        };
        Ok((
            input,
            BacnetObjectPropertyReferenceInfo::PropertyArrayIndex {
                property_array_index
            }
        ))
    }
    else {
        return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
    }
}

pub fn parse_bacnet_object_property_reference_item(input: &[u8]) -> IResult<&[u8], BacnetObjectPropertyReferenceItem> {
    let (input, (context_tag_number, tag_class, length_value_type)) = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
        tuple((take_bits(4usize), take_bits(1usize), take_bits(3usize)))
    )(input)?;
    let (input, bacnet_object_property_reference_info) = parse_bacnet_object_property_reference_info(input, context_tag_number, length_value_type)?;
    Ok((
        input,
        BacnetObjectPropertyReferenceItem {
            context_tag_number, tag_class, length_value_type,
            bacnet_object_property_reference_info
        }
    ))
}

fn parse_confirmed_service_request_acknowledge_alarm(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::AcknowledgeAlarm {
            
        }
    ))
}

fn parse_confirmed_service_request_confirmed_cov_notification(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::ConfirmedCovNotification {
            
        }
    ))
}

fn parse_confirmed_service_request_confirmed_event_notification(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::ConfirmedEventNotification {
            
        }
    ))
}

fn parse_confirmed_service_request_confirmed_get_alarm_summary(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::ConfirmedGetAlarmSummary {
            
        }
    ))
}

fn parse_confirmed_service_request_get_enrollment_summary(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::GetEnrollmentSummary {
            
        }
    ))
}

fn parse_confirmed_service_request_subscribe_cov(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::SubscribeCov {
            
        }
    ))
}

fn parse_confirmed_service_request_atomic_read_file(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::AtomicReadFile {
            
        }
    ))
}

fn parse_confirmed_service_request_atomic_write_file(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::AtomicWriteFile {
            
        }
    ))
}

fn parse_confirmed_service_request_add_list_element(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::AddListElement {
            
        }
    ))
}

fn parse_confirmed_service_request_remove_list_element(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::RemoveListElement {
            
        }
    ))
}

fn parse_confirmed_service_request_create_object(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::CreateObject {
            
        }
    ))
}

fn parse_confirmed_service_request_delete_object(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::DeleteObject {
            
        }
    ))
}

fn get_property_items_with_bacnet_object_property_reference_item(input: &[u8]) -> IResult<&[u8], Vec<BacnetObjectPropertyReferenceItem>> {
    let mut property_items = Vec::new();
    let mut _property_items: BacnetObjectPropertyReferenceItem;
    let mut input = input;

    while input.len() > 0 {
        (input, _property_items) = parse_bacnet_object_property_reference_item(input)?;
        property_items.push(_property_items);
    }

    Ok((
        input,
        property_items
    ))
}

fn parse_confirmed_service_request_read_property(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    let (input, property_items) = get_property_items_with_bacnet_object_property_reference_item(input)?;
    Ok((
        input,
        ConfirmedServiceRequest::ReadProperty {
            property_items
        }
    ))
}

fn parse_confirmed_service_request_read_property_conditional(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::ReadPropertyConditional {
            
        }
    ))
}

fn parse_confirmed_service_request_read_property_multiple(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::ReadPropertyMultiple {
            
        }
    ))
}

fn parse_confirmed_service_request_write_property(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::WriteProperty {
            
        }
    ))
}

fn parse_confirmed_service_request_write_property_multiple(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::WritePropertyMultiple {
            
        }
    ))
}

fn parse_confirmed_service_request_device_communication_control(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::DeviceCommunicationControl {
            
        }
    ))
}

fn parse_confirmed_service_request_confirmed_private_transfer(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::ConfirmedPrivateTransfer {
            
        }
    ))
}

fn parse_confirmed_service_request_confirmed_text_message(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::ConfirmedTextMessage {
            
        }
    ))
}

fn parse_confirmed_service_request_reinitialize_device(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::ReinitializeDevice {
            
        }
    ))
}

fn parse_confirmed_service_request_vt_open(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::VtOpen {
            
        }
    ))
}

fn parse_confirmed_service_request_vt_close(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::VtClose {
            
        }
    ))
}

fn parse_confirmed_service_request_vt_data(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::VtData {
            
        }
    ))
}

fn parse_confirmed_service_request_authenticate(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::Authenticate {
            
        }
    ))
}

fn parse_confirmed_service_request_request_key(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::RequestKey {
            
        }
    ))
}

fn parse_confirmed_service_request_read_range(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::ReadRange {
            
        }
    ))
}

fn parse_confirmed_service_request_life_safety_operation(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::LifeSafetyOperation {
            
        }
    ))
}

fn parse_confirmed_service_request_subscribe_cov_property(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::SubscribeCovProperty {
            
        }
    ))
}

fn parse_confirmed_service_request_get_event_information(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::GetEventInformation {
            
        }
    ))
}

fn parse_confirmed_service_request_subscribe_cov_property_multiple(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::SubscribeCovPropertyMultiple {
            
        }
    ))
}

fn parse_confirmed_service_request_confirmed_cov_notification_multiple(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::ConfirmedCovNotificationMultiple {
            
        }
    ))
}

fn parse_confirmed_service_request_confirmed_audit_notification(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::ConfirmedAuditNotification {
            
        }
    ))
}

fn parse_confirmed_service_request_audit_log_query(input: &[u8]) -> IResult<&[u8], ConfirmedServiceRequest> {
    Ok((
        input,
        ConfirmedServiceRequest::AuditLogQuery {
            
        }
    ))
}

pub fn parse_confirmed_service_request(input: &[u8], service_choice: u8) -> IResult<&[u8], ConfirmedServiceRequest> {
    let (input, confirmed_service_request) = match service_choice {
        0x0 => parse_confirmed_service_request_acknowledge_alarm(input),
        0x01 => parse_confirmed_service_request_confirmed_cov_notification(input),
        0x02 => parse_confirmed_service_request_confirmed_event_notification(input),
        0x03 => parse_confirmed_service_request_confirmed_get_alarm_summary(input),
        0x04 => parse_confirmed_service_request_get_enrollment_summary(input),
        0x05 => parse_confirmed_service_request_subscribe_cov(input),
        0x06 => parse_confirmed_service_request_atomic_read_file(input),
        0x07 => parse_confirmed_service_request_atomic_write_file(input),
        0x08 => parse_confirmed_service_request_add_list_element(input),
        0x09 => parse_confirmed_service_request_remove_list_element(input),
        0x0a => parse_confirmed_service_request_create_object(input),
        0x0b => parse_confirmed_service_request_delete_object(input),
        0x0c => parse_confirmed_service_request_read_property(input),
        0x0d => parse_confirmed_service_request_read_property_conditional(input),
        0x0e => parse_confirmed_service_request_read_property_multiple(input),
        0x0f => parse_confirmed_service_request_write_property(input),
        0x10 => parse_confirmed_service_request_write_property_multiple(input),
        0x11 => parse_confirmed_service_request_device_communication_control(input),
        0x12 => parse_confirmed_service_request_confirmed_private_transfer(input),
        0x13 => parse_confirmed_service_request_confirmed_text_message(input),
        0x14 => parse_confirmed_service_request_reinitialize_device(input),
        0x15 => parse_confirmed_service_request_vt_open(input),
        0x16 => parse_confirmed_service_request_vt_close(input),
        0x17 => parse_confirmed_service_request_vt_data(input),
        0x18 => parse_confirmed_service_request_authenticate(input),
        0x19 => parse_confirmed_service_request_request_key(input),
        0x1a => parse_confirmed_service_request_read_range(input),
        0x1b => parse_confirmed_service_request_life_safety_operation(input),
        0x1c => parse_confirmed_service_request_subscribe_cov_property(input),
        0x1d => parse_confirmed_service_request_get_event_information(input),
        0x1e => parse_confirmed_service_request_subscribe_cov_property_multiple(input),
        0x1f => parse_confirmed_service_request_confirmed_cov_notification_multiple(input),
        0x20 => parse_confirmed_service_request_confirmed_audit_notification(input),
        0x21 => parse_confirmed_service_request_audit_log_query(input),
        _ =>  Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }?;
    Ok((input, confirmed_service_request))
}



pub fn parse_bacnet_object_property_reference_ack_info(input: &[u8], context_tag_number: u8, length_value_type: u8) -> IResult<&[u8], BacnetObjectPropertyReferenceAckInfo> {
    if context_tag_number == 0 {
        let (input, (object_type, instance_number)) = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
            tuple((take_bits(10usize), take_bits(22usize)))
        )(input)?;
        Ok((
            input,
            BacnetObjectPropertyReferenceAckInfo::ObjectIdentifier {
                object_type, instance_number
            }
        ))
    }
    else if context_tag_number == 1 {
        let (input, property_identifier) = match take_bits::<_, _, _, nom::error::Error<(&[u8], usize)>>((length_value_type * 8) as usize)((input, 0 as usize)) {
            Ok(((input_remain, _offset), rst)) => (input_remain, rst),
            Err(_e) => return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Fail
            )))
        };
        Ok((
            input,
            BacnetObjectPropertyReferenceAckInfo::PropertyIdentifier {
                property_identifier
            }
        ))
    }
    else if context_tag_number == 2 {
        let (input, property_array_index) = match take_bits::<_, _, _, nom::error::Error<(&[u8], usize)>>((length_value_type * 8) as usize)((input, 0 as usize)) {
            Ok(((input_remain, _offset), rst)) => (input_remain, rst),
            Err(_e) => return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Fail
            )))
        };
        Ok((
            input,
            BacnetObjectPropertyReferenceAckInfo::PropertyArrayIndex {
                property_array_index
            }
        ))
    }
    else if context_tag_number == 3 && length_value_type == 6 {
        let (input, (app_context_tag_number, app_tag_class, app_length_value_type)) = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
            tuple((take_bits(4usize), take_bits(1usize), take_bits(3usize)))
        )(input)?;
        let (input, (object_type, instance_number)) = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
            tuple((take_bits(10usize), take_bits(22usize)))
        )(input)?;
        Ok((
            input,
            BacnetObjectPropertyReferenceAckInfo::PropertyValueOpen {
                app_context_tag_number, app_tag_class, app_length_value_type,
                object_type, instance_number
            }
        ))
    }
    else if context_tag_number == 3 && length_value_type == 7 {
        Ok((
            input,
            BacnetObjectPropertyReferenceAckInfo::PropertyValueClose {}
        ))
    }
    else {
        return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
    }
}

pub fn parse_bacnet_object_property_reference_ack_item(input: &[u8]) -> IResult<&[u8], BacnetObjectPropertyReferenceAckItem> {
    let (input, (context_tag_number, tag_class, length_value_type)) = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
        tuple((take_bits(4usize), take_bits(1usize), take_bits(3usize)))
    )(input)?;
    let (input, bacnet_object_property_reference_ack_info) = parse_bacnet_object_property_reference_ack_info(input, context_tag_number, length_value_type)?;
    Ok((
        input,
        BacnetObjectPropertyReferenceAckItem {
            context_tag_number, tag_class, length_value_type,
            bacnet_object_property_reference_ack_info
        }
    ))
}

fn parse_confirmed_service_ack_confirmed_event_notification_ack(input: &[u8]) -> IResult<&[u8], ConfirmedServiceAck> {
    Ok((
        input,
        ConfirmedServiceAck::ConfirmedEventNotificationAck {
            
        }
    ))
}

fn parse_confirmed_service_ack_get_enrollment_summary_ack(input: &[u8]) -> IResult<&[u8], ConfirmedServiceAck> {
    Ok((
        input,
        ConfirmedServiceAck::GetEnrollmentSummaryAck {
            
        }
    ))
}

fn parse_confirmed_service_ack_atomic_read_file(input: &[u8]) -> IResult<&[u8], ConfirmedServiceAck> {
    Ok((
        input,
        ConfirmedServiceAck::AtomicReadFile {
            
        }
    ))
}

fn parse_confirmed_service_ack_atomic_read_file_ack(input: &[u8]) -> IResult<&[u8], ConfirmedServiceAck> {
    Ok((
        input,
        ConfirmedServiceAck::AtomicReadFileAck {
            
        }
    ))
}

fn parse_confirmed_service_ack_create_object(input: &[u8]) -> IResult<&[u8], ConfirmedServiceAck> {
    Ok((
        input,
        ConfirmedServiceAck::CreateObject {
            
        }
    ))
}

fn get_property_items_with_bacnet_object_property_reference_ack_item(input: &[u8]) -> IResult<&[u8], Vec<BacnetObjectPropertyReferenceAckItem>> {
    let mut property_items = Vec::new();
    let mut _property_items: BacnetObjectPropertyReferenceAckItem;
    let mut input = input;

    while input.len() > 0 {
        (input, _property_items) = parse_bacnet_object_property_reference_ack_item(input)?;
        property_items.push(_property_items);
    }

    Ok((
        input,
        property_items
    ))
}

fn parse_confirmed_service_ack_read_property_ack(input: &[u8]) -> IResult<&[u8], ConfirmedServiceAck> {
    let (input, property_items) = get_property_items_with_bacnet_object_property_reference_ack_item(input)?;
    Ok((
        input,
        ConfirmedServiceAck::ReadPropertyAck {
            property_items
        }
    ))
}

fn parse_confirmed_service_ack_read_property_conditional_ack(input: &[u8]) -> IResult<&[u8], ConfirmedServiceAck> {
    Ok((
        input,
        ConfirmedServiceAck::ReadPropertyConditionalAck {
            
        }
    ))
}

fn parse_confirmed_service_ack_read_property_multiple_ack(input: &[u8]) -> IResult<&[u8], ConfirmedServiceAck> {
    Ok((
        input,
        ConfirmedServiceAck::ReadPropertyMultipleAck {
            
        }
    ))
}

fn parse_confirmed_service_ack_confirmed_private_transfer_ack(input: &[u8]) -> IResult<&[u8], ConfirmedServiceAck> {
    Ok((
        input,
        ConfirmedServiceAck::ConfirmedPrivateTransferAck {
            
        }
    ))
}

fn parse_confirmed_service_ack_vt_open_ack(input: &[u8]) -> IResult<&[u8], ConfirmedServiceAck> {
    Ok((
        input,
        ConfirmedServiceAck::VtOpenAck {
            
        }
    ))
}

fn parse_confirmed_service_ack_vt_data_ack(input: &[u8]) -> IResult<&[u8], ConfirmedServiceAck> {
    Ok((
        input,
        ConfirmedServiceAck::VtDataAck {
            
        }
    ))
}

fn parse_confirmed_service_ack_authenticate_ack(input: &[u8]) -> IResult<&[u8], ConfirmedServiceAck> {
    Ok((
        input,
        ConfirmedServiceAck::AuthenticateAck {
            
        }
    ))
}

fn parse_confirmed_service_ack_read_range_ack(input: &[u8]) -> IResult<&[u8], ConfirmedServiceAck> {
    Ok((
        input,
        ConfirmedServiceAck::ReadRangeAck {
            
        }
    ))
}

fn parse_confirmed_service_ack_get_event_information_ack(input: &[u8]) -> IResult<&[u8], ConfirmedServiceAck> {
    Ok((
        input,
        ConfirmedServiceAck::GetEventInformationACK {
            
        }
    ))
}

fn parse_confirmed_service_ack_audit_log_query_ack(input: &[u8]) -> IResult<&[u8], ConfirmedServiceAck> {
    Ok((
        input,
        ConfirmedServiceAck::AuditLogQueryAck {
            
        }
    ))
}

pub fn parse_confirmed_service_ack(input: &[u8], service_choice: u8) -> IResult<&[u8], ConfirmedServiceAck> {
    let (input, confirmed_service_ack) = match service_choice {
        0x03 => parse_confirmed_service_ack_confirmed_event_notification_ack(input),
        0x04 => parse_confirmed_service_ack_get_enrollment_summary_ack(input),
        0x06 => parse_confirmed_service_ack_atomic_read_file(input),
        0x07 => parse_confirmed_service_ack_atomic_read_file_ack(input),
        0x0a => parse_confirmed_service_ack_create_object(input),
        0x0c => parse_confirmed_service_ack_read_property_ack(input),
        0x0d => parse_confirmed_service_ack_read_property_conditional_ack(input),
        0x0e => parse_confirmed_service_ack_read_property_multiple_ack(input),
        0x12 => parse_confirmed_service_ack_confirmed_private_transfer_ack(input),
        0x15 => parse_confirmed_service_ack_vt_open_ack(input),
        0x17 => parse_confirmed_service_ack_vt_data_ack(input),
        0x18 => parse_confirmed_service_ack_authenticate_ack(input),
        0x1a => parse_confirmed_service_ack_read_range_ack(input),
        0x1d => parse_confirmed_service_ack_get_event_information_ack(input),
        0x21 => parse_confirmed_service_ack_audit_log_query_ack(input),
        _ =>  Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }?;
    Ok((input, confirmed_service_ack))
}



pub fn parse_apdu_info(input: &[u8], apdu_type: u8, pdu_flags: u8) -> IResult<&[u8], ApduInfo> {
    if apdu_type == 0 {
        let (input, (unknow_bit, response_segments, max_adpu_size)) = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
            tuple((take_bits(1usize), take_bits(3usize), take_bits(4usize)))
        )(input)?;
        let (input, invoke_id) = u8(input)?;
        let (input, segmented_req_info) = parse_segmented_req_info(input, pdu_flags)?;
        let (input, service_choice) = u8(input)?;
        let (input, confirmed_service_request) = parse_confirmed_service_request(input, service_choice)?;
        Ok((
            input,
            ApduInfo::ComfirmedServiceRequest {
                unknow_bit, response_segments, max_adpu_size,
                invoke_id,
                segmented_req_info,
                service_choice,
                confirmed_service_request
            }
        ))
    }
    else if apdu_type == 3 {
        let (input, invoke_id) = u8(input)?;
        let (input, segmented_req_info) = parse_segmented_req_info(input, pdu_flags)?;
        let (input, service_choice) = u8(input)?;
        let (input, confirmed_service_ack) = parse_confirmed_service_ack(input, service_choice)?;
        Ok((
            input,
            ApduInfo::ComplexAckPdu {
                invoke_id,
                segmented_req_info,
                service_choice,
                confirmed_service_ack
            }
        ))
    }
    else {
        return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
    }
}



pub fn parse_apdu_option<'a>(input: &'a[u8], npdu: &Npdu<'a>) -> IResult<&'a[u8], ApduOption<'a>> {
    let (input, apdu_option) = match npdu.control & 0x80 {
        0x80 => {
            let (input, unknow_data) = take(input.len() as usize)(input)?;
            Ok((
                input,
                ApduOption::UnknowApdu {
                    unknow_data
                }
            ))
        }
        0x0 => {
            let (input, (apdu_type, pdu_flags)) = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
                tuple((take_bits(4usize), take_bits(4usize)))
            )(input)?;
            let (input, apdu_info) = parse_apdu_info(input, apdu_type, pdu_flags)?;
            Ok((
                input,
                ApduOption::Apdu {
                    apdu_type, pdu_flags,
                    apdu_info
                }
            ))
        }
        _ =>  Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))),
    }?;
    Ok((input, apdu_option))
}