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
use nom::number::complete::{be_u16, be_u24, be_u32, be_u64, le_u16, le_u24, le_u32, le_u64, u8};
#[allow(unused)]
use nom::sequence::tuple;
#[allow(unused)]
use nom::IResult;
#[allow(unused)]
use tracing::{debug, error};

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
#[allow(unused)]
use crate::protocol::*;
#[allow(unused)]
use crate::utils::*;
#[allow(unused)]
use crate::ProtocolType;

#[allow(unused)]
use std::convert::TryInto;
#[allow(unused)]
use std::ops::BitAnd;
#[allow(unused)]
use std::ops::BitOr;
#[allow(unused)]
use std::ops::BitXor;

use super::parse_l5_eof_layer;

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OpcuaHeader<'a> {
    pub message_type: u32,
    pub message_type_enum: MessageTypeEnum<'a>,
}

pub fn parse_opcua_header(input: &[u8]) -> IResult<&[u8], OpcuaHeader> {
    let (input, message_type) = be_u24(input)?;
    let (input, message_type_enum) = parse_message_type_enum(input, message_type)?;
    Ok((
        input,
        OpcuaHeader {
            message_type,
            message_type_enum,
        },
    ))
}

pub fn parse_opcua_layer<'a>(
    input: &'a [u8],
    link_layer: LinkLayer,
    network_layer: NetworkLayer<'a>,
    transport_layer: TransportLayer<'a>,
    options: &QuinPacketOptions,
) -> QuinPacket<'a> {
    let current_prototype = ProtocolType::Application(ApplicationProtocol::Opcua);

    let (input, opcua_header) = match parse_opcua_header(input) {
        Ok(o) => o,
        Err(e) => {
            error!(
                target: "PARSER(opcua::parse_opcua_layer)",
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
            });
        }
    };

    if Some(current_prototype) == options.stop {
        let application_layer = ApplicationLayer::Opcua(opcua_header);
        return QuinPacket::L5(L5Packet {
            link_layer,
            network_layer,
            transport_layer,
            application_layer,
            error: None,
            remain: input,
        });
    };

    let application_layer = ApplicationLayer::Opcua(opcua_header);
    return parse_l5_eof_layer(
        input,
        link_layer,
        network_layer,
        transport_layer,
        application_layer,
        options,
    );
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OpcuaString<'a> {
    pub string_len: u32,
    pub string_data: &'a str,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum NamespaceEnum<'a> {
    HasNamespace { namespace_uri: &'a str },
    NoNamespace {},
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ServerIndexEnum {
    HasServerIndex { server_index: u32 },
    NoServerIndex {},
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum NodeidInfo {
    TB {
        nodeid_numeric: u8,
    },
    FB {
        nodeid_namespace: u8,
        nodeid_numeric: u16,
    },
    Numeric {
        nodeid_namespace: u16,
        nodeid_numeric: u32,
    },
    String {
        nodeid_namespace: u16,
    },
    Guid {
        nodeid_namespace: u16,
    },
    Opaque {
        nodeid_namespace: u16,
    },
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ExpandedNodeIdInfo<'a> {
    TB {
        nodeid_numeric: u8,
        namespace_enum: NamespaceEnum<'a>,
        server_index_enum: ServerIndexEnum,
    },
    FB {
        nodeid_namespace: u8,
        nodeid_numeric: u16,
        namespace_enum: NamespaceEnum<'a>,
        server_index_enum: ServerIndexEnum,
    },
    Numeric {
        nodeid_namespace: u16,
        nodeid_numeric: u32,
        namespace_enum: NamespaceEnum<'a>,
        server_index_enum: ServerIndexEnum,
    },
    String {
        nodeid_namespace: u16,
        namespace_enum: NamespaceEnum<'a>,
        server_index_enum: ServerIndexEnum,
    },
    Guid {
        nodeid_namespace: u16,
        namespace_enum: NamespaceEnum<'a>,
        server_index_enum: ServerIndexEnum,
    },
    Opaque {
        nodeid_namespace: u16,
        namespace_enum: NamespaceEnum<'a>,
        server_index_enum: ServerIndexEnum,
    },
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RequestHeader<'a> {
    pub nodeid_encodingmask: u8,
    pub nodeid_info: NodeidInfo,
    pub timestamp: u64,
    pub request_handle: u32,
    pub sl_symbolic_id: u8,
    pub sl_localized_text: u8,
    pub sl_additional_info: u8,
    pub sl_inner_status_code: u8,
    pub sl_inner_diagnostics: u8,
    pub ol_symbolic_id: u8,
    pub ol_localized_text: u8,
    pub ol_additional_info: u8,
    pub ol_inner_status_code: u8,
    pub ol_inner_diagnostics: u8,
    pub audit_entryid: &'a str,
    pub timeout_hint: u32,
    pub expanded_nodeid_has_namespace_uri: u8,
    pub expanded_nodeid_has_server_index: u8,
    pub expanded_nodeid_encodingmask: u8,
    pub expanded_node_id_info: ExpandedNodeIdInfo<'a>,
    pub encodingmask_has_binary_body: u8,
    pub encodingmask_has_xml_body: u8,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ServiceEnum<'a> {
    ServiceFault {},
    FindServersRequest {},
    FindServersResponse {},
    FindServersOnNetworkRequest {},
    FindServersOnNetworkResponse {},
    GetEndpointsRequest {
        request_header: RequestHeader<'a>,
        endpoint_url: &'a str,
        locale_ids_array_size: u32,
        locale_ids_array_string_items: Vec<OpcuaString<'a>>,
        profile_uris_array_size: u32,
        profile_uris_array_string_items: Vec<OpcuaString<'a>>,
    },
    GetEndpointsResponse {},
    RegisterServerRequest {},
    RegisterServerResponse {},
    RegisterServer2Request {},
    RegisterServer2Response {},
    OpenSecureChannelRequest {},
    OpenSecureChannelResponse {},
    CloseSecureChannelRequest {},
    CloseSecureChannelResponse {},
    CreateSessionRequest {},
    CreateSessionResponse {},
    ActivateSessionRequest {},
    ActivateSessionResponse {},
    CloseSessionRequest {},
    CloseSessionResponse {},
    CancelRequest {},
    CancelResponse {},
    AddNodesRequest {},
    AddNodesResponse {},
    AddReferencesRequest {},
    AddReferencesResponse {},
    DeleteNodesRequest {},
    DeleteNodesResponse {},
    DeleteReferencesRequest {},
    DeleteReferencesResponse {},
    BrowseRequest {},
    BrowseResponse {},
    BrowseNextRequest {},
    BrowseNextResponse {},
    TranslateBrowsePathsToNodeIdsRequest {},
    TranslateBrowsePathsToNodeIdsResponse {},
    RegisterNodesRequest {},
    RegisterNodesResponse {},
    UnregisterNodesRequest {},
    UnregisterNodesResponse {},
    QueryFirstRequest {},
    QueryFirstResponse {},
    QueryNextRequest {},
    QueryNextResponse {},
    ReadRequest {},
    ReadResponse {},
    HistoryReadRequest {},
    HistoryReadResponse {},
    WriteRequest {},
    WriteResponse {},
    HistoryUpdateRequest {},
    HistoryUpdateResponse {},
    CallRequest {},
    CallResponse {},
    CreateMonitoredItemsRequest {},
    CreateMonitoredItemsResponse {},
    ModifyMonitoredItemsRequest {},
    ModifyMonitoredItemsResponse {},
    SetMonitoringModeRequest {},
    SetMonitoringModeResponse {},
    SetTriggeringRequest {},
    SetTriggeringResponse {},
    DeleteMonitoredItemsRequest {},
    DeleteMonitoredItemsResponse {},
    CreateSubscriptionRequest {},
    CreateSubscriptionResponse {},
    ModifySubscriptionRequest {},
    ModifySubscriptionResponse {},
    SetPublishingModeRequest {},
    SetPublishingModeResponse {},
    PublishRequest {},
    PublishResponse {},
    RepublishRequest {},
    RepublishResponse {},
    TransferSubscriptionsRequest {},
    TransferSubscriptionsResponse {},
    DeleteSubscriptionsRequest {},
    DeleteSubscriptionsResponse {},
    TestStackRequest {},
    TestStackResponse {},
    TestStackExRequest {},
    TestStackExResponse {},
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ServiceNodeidInfo<'a> {
    TB {
        service_nodeid_numeric: u8,
        service_enum: ServiceEnum<'a>,
    },
    FB {
        service_nodeid_namespace: u8,
        service_nodeid_numeric: u16,
        service_enum: ServiceEnum<'a>,
    },
    Numeric {
        service_nodeid_namespace: u16,
        service_nodeid_numeric: u32,
        service_enum: ServiceEnum<'a>,
    },
    String {},
    Guid {},
    Opaque {},
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MsgVariantInfo<'a> {
    Abort {
        error: &'a str,
        reason: &'a str,
    },
    Service {
        service_nodeid_encodingmask: u8,
        service_nodeid_info: ServiceNodeidInfo<'a>,
    },
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MessageTypeEnum<'a> {
    Hello {
        chunk_type: u8,
        transport_size: u32,
        version: u32,
        receive_buffer_size: u32,
        send_buffer_size: u32,
        max_message_size: u32,
        max_chunk_count: u32,
        endpoint_url: &'a str,
    },
    Acknowledge {
        chunk_type: u8,
        transport_size: u32,
        version: u32,
        receive_buffer_size: u32,
        send_buffer_size: u32,
        max_message_size: u32,
        max_chunk_count: u32,
    },
    Error {
        chunk_type: u8,
        transport_size: u32,
        error: u32,
        reason: u32,
    },
    ReverseHello {
        chunk_type: u8,
        transport_size: u32,
        suri: &'a str,
        endpoint_url: &'a str,
    },
    Message {
        chunk_type: u8,
        transport_size: u32,
        secure_channel_id: u32,
        security_token_id: u32,
        security_sequence_number: u32,
        security_request_id: u32,
        msg_variant_info: MsgVariantInfo<'a>,
    },
    OpenSecureChannel {},
    CloseSecureChannel {},
}

pub fn parse_opcua_string(input: &[u8]) -> IResult<&[u8], OpcuaString> {
    let (input, string_len) = le_u32(input)?;
    let mut string_len = string_len;
    if string_len == 0xffffffff {
        string_len = 0;
    }
    let (input, _string_data) = take(string_len as usize)(input)?;
    let string_data = match std::str::from_utf8(_string_data) {
        Ok(o) => o,
        Err(_) => {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Verify,
            )))
        }
    };
    Ok((
        input,
        OpcuaString {
            string_len,
            string_data,
        },
    ))
}

fn parse_namespace_enum_has_namespace(input: &[u8]) -> IResult<&[u8], NamespaceEnum> {
    let (input, _namespace_uri_len) = le_u32(input)?;
    let mut _namespace_uri_len = _namespace_uri_len;
    if _namespace_uri_len == 0xffffffff {
        _namespace_uri_len = 0;
    }
    let (input, _namespace_uri) = take(_namespace_uri_len as usize)(input)?;
    let namespace_uri = match std::str::from_utf8(_namespace_uri) {
        Ok(o) => o,
        Err(_) => {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Verify,
            )))
        }
    };
    Ok((input, NamespaceEnum::HasNamespace { namespace_uri }))
}

#[inline(always)]
fn parse_namespace_enum_no_namespace(input: &[u8]) -> IResult<&[u8], NamespaceEnum> {
    Ok((input, NamespaceEnum::NoNamespace {}))
}

pub fn parse_namespace_enum(
    input: &[u8],
    expanded_nodeid_has_namespace_uri: u8,
) -> IResult<&[u8], NamespaceEnum> {
    let (input, namespace_enum) = match expanded_nodeid_has_namespace_uri {
        0x01 => parse_namespace_enum_has_namespace(input),
        0x0 => parse_namespace_enum_no_namespace(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, namespace_enum))
}

fn parse_server_index_enum_has_server_index(input: &[u8]) -> IResult<&[u8], ServerIndexEnum> {
    let (input, server_index) = le_u32(input)?;
    Ok((input, ServerIndexEnum::HasServerIndex { server_index }))
}

#[inline(always)]
fn parse_server_index_enum_no_server_index(input: &[u8]) -> IResult<&[u8], ServerIndexEnum> {
    Ok((input, ServerIndexEnum::NoServerIndex {}))
}

pub fn parse_server_index_enum(
    input: &[u8],
    expanded_nodeid_has_server_index: u8,
) -> IResult<&[u8], ServerIndexEnum> {
    let (input, server_index_enum) = match expanded_nodeid_has_server_index {
        0x01 => parse_server_index_enum_has_server_index(input),
        0x0 => parse_server_index_enum_no_server_index(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, server_index_enum))
}

fn parse_nodeid_info_tb(input: &[u8]) -> IResult<&[u8], NodeidInfo> {
    let (input, nodeid_numeric) = u8(input)?;
    Ok((input, NodeidInfo::TB { nodeid_numeric }))
}

fn parse_nodeid_info_fb(input: &[u8]) -> IResult<&[u8], NodeidInfo> {
    let (input, nodeid_namespace) = u8(input)?;
    let (input, nodeid_numeric) = le_u16(input)?;
    Ok((
        input,
        NodeidInfo::FB {
            nodeid_namespace,
            nodeid_numeric,
        },
    ))
}

fn parse_nodeid_info_numeric(input: &[u8]) -> IResult<&[u8], NodeidInfo> {
    let (input, nodeid_namespace) = le_u16(input)?;
    let (input, nodeid_numeric) = le_u32(input)?;
    Ok((
        input,
        NodeidInfo::Numeric {
            nodeid_namespace,
            nodeid_numeric,
        },
    ))
}

fn parse_nodeid_info_string(input: &[u8]) -> IResult<&[u8], NodeidInfo> {
    let (input, nodeid_namespace) = le_u16(input)?;
    Ok((input, NodeidInfo::String { nodeid_namespace }))
}

fn parse_nodeid_info_guid(input: &[u8]) -> IResult<&[u8], NodeidInfo> {
    let (input, nodeid_namespace) = le_u16(input)?;
    Ok((input, NodeidInfo::Guid { nodeid_namespace }))
}

fn parse_nodeid_info_opaque(input: &[u8]) -> IResult<&[u8], NodeidInfo> {
    let (input, nodeid_namespace) = le_u16(input)?;
    Ok((input, NodeidInfo::Opaque { nodeid_namespace }))
}

pub fn parse_nodeid_info(input: &[u8], nodeid_encodingmask: u8) -> IResult<&[u8], NodeidInfo> {
    let (input, nodeid_info) = match nodeid_encodingmask {
        0x0 => parse_nodeid_info_tb(input),
        0x01 => parse_nodeid_info_fb(input),
        0x02 => parse_nodeid_info_numeric(input),
        0x03 => parse_nodeid_info_string(input),
        0x04 => parse_nodeid_info_guid(input),
        0x05 => parse_nodeid_info_opaque(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, nodeid_info))
}

pub fn parse_expanded_node_id_info(
    input: &[u8],
    expanded_nodeid_encodingmask: u8,
    expanded_nodeid_has_namespace_uri: u8,
    expanded_nodeid_has_server_index: u8,
) -> IResult<&[u8], ExpandedNodeIdInfo> {
    if expanded_nodeid_encodingmask == 0x00 {
        let (input, nodeid_numeric) = u8(input)?;
        let (input, namespace_enum) =
            parse_namespace_enum(input, expanded_nodeid_has_namespace_uri)?;
        let (input, server_index_enum) =
            parse_server_index_enum(input, expanded_nodeid_has_server_index)?;
        Ok((
            input,
            ExpandedNodeIdInfo::TB {
                nodeid_numeric,
                namespace_enum,
                server_index_enum,
            },
        ))
    } else if expanded_nodeid_encodingmask == 0x01 {
        let (input, nodeid_namespace) = u8(input)?;
        let (input, nodeid_numeric) = le_u16(input)?;
        let (input, namespace_enum) =
            parse_namespace_enum(input, expanded_nodeid_has_namespace_uri)?;
        let (input, server_index_enum) =
            parse_server_index_enum(input, expanded_nodeid_has_server_index)?;
        Ok((
            input,
            ExpandedNodeIdInfo::FB {
                nodeid_namespace,
                nodeid_numeric,
                namespace_enum,
                server_index_enum,
            },
        ))
    } else if expanded_nodeid_encodingmask == 0x02 {
        let (input, nodeid_namespace) = le_u16(input)?;
        let (input, nodeid_numeric) = le_u32(input)?;
        let (input, namespace_enum) =
            parse_namespace_enum(input, expanded_nodeid_has_namespace_uri)?;
        let (input, server_index_enum) =
            parse_server_index_enum(input, expanded_nodeid_has_server_index)?;
        Ok((
            input,
            ExpandedNodeIdInfo::Numeric {
                nodeid_namespace,
                nodeid_numeric,
                namespace_enum,
                server_index_enum,
            },
        ))
    } else if expanded_nodeid_encodingmask == 0x03 {
        let (input, nodeid_namespace) = le_u16(input)?;
        let (input, namespace_enum) =
            parse_namespace_enum(input, expanded_nodeid_has_namespace_uri)?;
        let (input, server_index_enum) =
            parse_server_index_enum(input, expanded_nodeid_has_server_index)?;
        Ok((
            input,
            ExpandedNodeIdInfo::String {
                nodeid_namespace,
                namespace_enum,
                server_index_enum,
            },
        ))
    } else if expanded_nodeid_encodingmask == 0x04 {
        let (input, nodeid_namespace) = le_u16(input)?;
        let (input, namespace_enum) =
            parse_namespace_enum(input, expanded_nodeid_has_namespace_uri)?;
        let (input, server_index_enum) =
            parse_server_index_enum(input, expanded_nodeid_has_server_index)?;
        Ok((
            input,
            ExpandedNodeIdInfo::Guid {
                nodeid_namespace,
                namespace_enum,
                server_index_enum,
            },
        ))
    } else if expanded_nodeid_encodingmask == 0x05 {
        let (input, nodeid_namespace) = le_u16(input)?;
        let (input, namespace_enum) =
            parse_namespace_enum(input, expanded_nodeid_has_namespace_uri)?;
        let (input, server_index_enum) =
            parse_server_index_enum(input, expanded_nodeid_has_server_index)?;
        Ok((
            input,
            ExpandedNodeIdInfo::Opaque {
                nodeid_namespace,
                namespace_enum,
                server_index_enum,
            },
        ))
    } else {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )));
    }
}

pub fn parse_request_header(input: &[u8]) -> IResult<&[u8], RequestHeader> {
    let (input, (_, nodeid_encodingmask)): (&[u8], (u8, u8)) =
        bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
            take_bits(4usize),
            take_bits(4usize),
        )))(input)?;
    let (input, nodeid_info) = parse_nodeid_info(input, nodeid_encodingmask)?;
    let (input, timestamp) = be_u64(input)?;
    let (input, request_handle) = le_u32(input)?;
    let (
        input,
        (
            sl_symbolic_id,
            sl_localized_text,
            sl_additional_info,
            sl_inner_status_code,
            sl_inner_diagnostics,
            ol_symbolic_id,
            ol_localized_text,
            ol_additional_info,
            ol_inner_status_code,
            ol_inner_diagnostics,
            _,
        ),
    ): (&[u8], (u8, u8, u8, u8, u8, u8, u8, u8, u8, u8, u32)) =
        bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
            take_bits(1usize),
            take_bits(1usize),
            take_bits(1usize),
            take_bits(1usize),
            take_bits(1usize),
            take_bits(1usize),
            take_bits(1usize),
            take_bits(1usize),
            take_bits(1usize),
            take_bits(1usize),
            take_bits(22usize),
        )))(input)?;
    let (input, _audit_entryid_len) = le_u32(input)?;
    let mut _audit_entryid_len = _audit_entryid_len;
    if _audit_entryid_len == 0xffffffff {
        _audit_entryid_len = 0;
    }
    let (input, _audit_entryid) = take(_audit_entryid_len as usize)(input)?;
    let audit_entryid = match std::str::from_utf8(_audit_entryid) {
        Ok(o) => o,
        Err(_) => {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Verify,
            )))
        }
    };
    let (input, timeout_hint) = le_u32(input)?;
    let (
        input,
        (
            expanded_nodeid_has_namespace_uri,
            expanded_nodeid_has_server_index,
            _,
            expanded_nodeid_encodingmask,
        ),
    ): (&[u8], (u8, u8, u8, u8)) = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
        take_bits(1usize),
        take_bits(1usize),
        take_bits(2usize),
        take_bits(4usize),
    )))(input)?;
    let (input, expanded_node_id_info) = parse_expanded_node_id_info(
        input,
        expanded_nodeid_encodingmask,
        expanded_nodeid_has_namespace_uri,
        expanded_nodeid_has_server_index,
    )?;
    let (input, (_, encodingmask_has_binary_body, encodingmask_has_xml_body)): (
        &[u8],
        (u8, u8, u8),
    ) = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
        take_bits(6usize),
        take_bits(1usize),
        take_bits(1usize),
    )))(input)?;
    Ok((
        input,
        RequestHeader {
            nodeid_encodingmask,
            nodeid_info,
            timestamp,
            request_handle,
            sl_symbolic_id,
            sl_localized_text,
            sl_additional_info,
            sl_inner_status_code,
            sl_inner_diagnostics,
            ol_symbolic_id,
            ol_localized_text,
            ol_additional_info,
            ol_inner_status_code,
            ol_inner_diagnostics,
            audit_entryid,
            timeout_hint,
            expanded_nodeid_has_namespace_uri,
            expanded_nodeid_has_server_index,
            expanded_nodeid_encodingmask,
            expanded_node_id_info,
            encodingmask_has_binary_body,
            encodingmask_has_xml_body,
        },
    ))
}

fn parse_service_enum_service_fault(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::ServiceFault {}))
}

fn parse_service_enum_find_servers_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::FindServersRequest {}))
}

fn parse_service_enum_find_servers_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::FindServersResponse {}))
}

fn parse_service_enum_find_servers_on_network_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::FindServersOnNetworkRequest {}))
}

fn parse_service_enum_find_servers_on_network_response(
    input: &[u8],
) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::FindServersOnNetworkResponse {}))
}

fn parse_service_enum_get_endpoints_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    let (input, request_header) = parse_request_header(input)?;
    let (input, _endpoint_url_len) = le_u32(input)?;
    let mut _endpoint_url_len = _endpoint_url_len;
    if _endpoint_url_len == 0xffffffff {
        _endpoint_url_len = 0;
    }
    let (input, _endpoint_url) = take(_endpoint_url_len as usize)(input)?;
    let endpoint_url = match std::str::from_utf8(_endpoint_url) {
        Ok(o) => o,
        Err(_) => {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Verify,
            )))
        }
    };
    let (input, locale_ids_array_size) = le_u32(input)?;
    let (input, locale_ids_array_string_items) =
        count(parse_opcua_string, locale_ids_array_size as usize)(input)?;
    let (input, profile_uris_array_size) = le_u32(input)?;
    let (input, profile_uris_array_string_items) =
        count(parse_opcua_string, profile_uris_array_size as usize)(input)?;
    Ok((
        input,
        ServiceEnum::GetEndpointsRequest {
            request_header,
            endpoint_url,
            locale_ids_array_size,
            locale_ids_array_string_items,
            profile_uris_array_size,
            profile_uris_array_string_items,
        },
    ))
}

fn parse_service_enum_get_endpoints_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::GetEndpointsResponse {}))
}

fn parse_service_enum_register_server_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::RegisterServerRequest {}))
}

fn parse_service_enum_register_server_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::RegisterServerResponse {}))
}

fn parse_service_enum_register_server2_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::RegisterServer2Request {}))
}

fn parse_service_enum_register_server2_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::RegisterServer2Response {}))
}

fn parse_service_enum_open_secure_channel_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::OpenSecureChannelRequest {}))
}

fn parse_service_enum_open_secure_channel_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::OpenSecureChannelResponse {}))
}

fn parse_service_enum_close_secure_channel_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::CloseSecureChannelRequest {}))
}

fn parse_service_enum_close_secure_channel_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::CloseSecureChannelResponse {}))
}

fn parse_service_enum_create_session_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::CreateSessionRequest {}))
}

fn parse_service_enum_create_session_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::CreateSessionResponse {}))
}

fn parse_service_enum_activate_session_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::ActivateSessionRequest {}))
}

fn parse_service_enum_activate_session_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::ActivateSessionResponse {}))
}

fn parse_service_enum_close_session_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::CloseSessionRequest {}))
}

fn parse_service_enum_close_session_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::CloseSessionResponse {}))
}

fn parse_service_enum_cancel_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::CancelRequest {}))
}

fn parse_service_enum_cancel_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::CancelResponse {}))
}

fn parse_service_enum_add_nodes_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::AddNodesRequest {}))
}

fn parse_service_enum_add_nodes_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::AddNodesResponse {}))
}

fn parse_service_enum_add_references_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::AddReferencesRequest {}))
}

fn parse_service_enum_add_references_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::AddReferencesResponse {}))
}

fn parse_service_enum_delete_nodes_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::DeleteNodesRequest {}))
}

fn parse_service_enum_delete_nodes_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::DeleteNodesResponse {}))
}

fn parse_service_enum_delete_references_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::DeleteReferencesRequest {}))
}

fn parse_service_enum_delete_references_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::DeleteReferencesResponse {}))
}

fn parse_service_enum_browse_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::BrowseRequest {}))
}

fn parse_service_enum_browse_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::BrowseResponse {}))
}

fn parse_service_enum_browse_next_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::BrowseNextRequest {}))
}

fn parse_service_enum_browse_next_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::BrowseNextResponse {}))
}

fn parse_service_enum_translate_browse_paths_to_node_ids_request(
    input: &[u8],
) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::TranslateBrowsePathsToNodeIdsRequest {}))
}

fn parse_service_enum_translate_browse_paths_to_node_ids_response(
    input: &[u8],
) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::TranslateBrowsePathsToNodeIdsResponse {}))
}

fn parse_service_enum_register_nodes_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::RegisterNodesRequest {}))
}

fn parse_service_enum_register_nodes_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::RegisterNodesResponse {}))
}

fn parse_service_enum_unregister_nodes_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::UnregisterNodesRequest {}))
}

fn parse_service_enum_unregister_nodes_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::UnregisterNodesResponse {}))
}

fn parse_service_enum_query_first_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::QueryFirstRequest {}))
}

fn parse_service_enum_query_first_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::QueryFirstResponse {}))
}

fn parse_service_enum_query_next_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::QueryNextRequest {}))
}

fn parse_service_enum_query_next_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::QueryNextResponse {}))
}

fn parse_service_enum_read_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::ReadRequest {}))
}

fn parse_service_enum_read_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::ReadResponse {}))
}

fn parse_service_enum_history_read_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::HistoryReadRequest {}))
}

fn parse_service_enum_history_read_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::HistoryReadResponse {}))
}

fn parse_service_enum_write_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::WriteRequest {}))
}

fn parse_service_enum_write_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::WriteResponse {}))
}

fn parse_service_enum_history_update_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::HistoryUpdateRequest {}))
}

fn parse_service_enum_history_update_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::HistoryUpdateResponse {}))
}

fn parse_service_enum_call_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::CallRequest {}))
}

fn parse_service_enum_call_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::CallResponse {}))
}

fn parse_service_enum_create_monitored_items_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::CreateMonitoredItemsRequest {}))
}

fn parse_service_enum_create_monitored_items_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::CreateMonitoredItemsResponse {}))
}

fn parse_service_enum_modify_monitored_items_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::ModifyMonitoredItemsRequest {}))
}

fn parse_service_enum_modify_monitored_items_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::ModifyMonitoredItemsResponse {}))
}

fn parse_service_enum_set_monitoring_mode_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::SetMonitoringModeRequest {}))
}

fn parse_service_enum_set_monitoring_mode_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::SetMonitoringModeResponse {}))
}

fn parse_service_enum_set_triggering_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::SetTriggeringRequest {}))
}

fn parse_service_enum_set_triggering_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::SetTriggeringResponse {}))
}

fn parse_service_enum_delete_monitored_items_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::DeleteMonitoredItemsRequest {}))
}

fn parse_service_enum_delete_monitored_items_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::DeleteMonitoredItemsResponse {}))
}

fn parse_service_enum_create_subscription_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::CreateSubscriptionRequest {}))
}

fn parse_service_enum_create_subscription_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::CreateSubscriptionResponse {}))
}

fn parse_service_enum_modify_subscription_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::ModifySubscriptionRequest {}))
}

fn parse_service_enum_modify_subscription_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::ModifySubscriptionResponse {}))
}

fn parse_service_enum_set_publishing_mode_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::SetPublishingModeRequest {}))
}

fn parse_service_enum_set_publishing_mode_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::SetPublishingModeResponse {}))
}

fn parse_service_enum_publish_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::PublishRequest {}))
}

fn parse_service_enum_publish_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::PublishResponse {}))
}

fn parse_service_enum_republish_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::RepublishRequest {}))
}

fn parse_service_enum_republish_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::RepublishResponse {}))
}

fn parse_service_enum_transfer_subscriptions_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::TransferSubscriptionsRequest {}))
}

fn parse_service_enum_transfer_subscriptions_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::TransferSubscriptionsResponse {}))
}

fn parse_service_enum_delete_subscriptions_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::DeleteSubscriptionsRequest {}))
}

fn parse_service_enum_delete_subscriptions_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::DeleteSubscriptionsResponse {}))
}

fn parse_service_enum_test_stack_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::TestStackRequest {}))
}

fn parse_service_enum_test_stack_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::TestStackResponse {}))
}

fn parse_service_enum_test_stack_ex_request(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::TestStackExRequest {}))
}

fn parse_service_enum_test_stack_ex_response(input: &[u8]) -> IResult<&[u8], ServiceEnum> {
    Ok((input, ServiceEnum::TestStackExResponse {}))
}

pub fn parse_service_enum(
    input: &[u8],
    service_nodeid_numeric: u32,
) -> IResult<&[u8], ServiceEnum> {
    let (input, service_enum) = match service_nodeid_numeric {
        0x018d => parse_service_enum_service_fault(input),
        0x01a6 => parse_service_enum_find_servers_request(input),
        0x01a9 => parse_service_enum_find_servers_response(input),
        0x2fb0 => parse_service_enum_find_servers_on_network_request(input),
        0x2fb1 => parse_service_enum_find_servers_on_network_response(input),
        0x01ac => parse_service_enum_get_endpoints_request(input),
        0x01af => parse_service_enum_get_endpoints_response(input),
        0x01b5 => parse_service_enum_register_server_request(input),
        0x01b8 => parse_service_enum_register_server_response(input),
        0x2fb3 => parse_service_enum_register_server2_request(input),
        0x2fb4 => parse_service_enum_register_server2_response(input),
        0x01be => parse_service_enum_open_secure_channel_request(input),
        0x01c1 => parse_service_enum_open_secure_channel_response(input),
        0x01c4 => parse_service_enum_close_secure_channel_request(input),
        0x01c7 => parse_service_enum_close_secure_channel_response(input),
        0x01cd => parse_service_enum_create_session_request(input),
        0x01d0 => parse_service_enum_create_session_response(input),
        0x01d3 => parse_service_enum_activate_session_request(input),
        0x01d6 => parse_service_enum_activate_session_response(input),
        0x01d9 => parse_service_enum_close_session_request(input),
        0x01dc => parse_service_enum_close_session_response(input),
        0x01df => parse_service_enum_cancel_request(input),
        0x01e2 => parse_service_enum_cancel_response(input),
        0x01e8 => parse_service_enum_add_nodes_request(input),
        0x01eb => parse_service_enum_add_nodes_response(input),
        0x01ee => parse_service_enum_add_references_request(input),
        0x01f1 => parse_service_enum_add_references_response(input),
        0x01f4 => parse_service_enum_delete_nodes_request(input),
        0x01f7 => parse_service_enum_delete_nodes_response(input),
        0x01fa => parse_service_enum_delete_references_request(input),
        0x01fd => parse_service_enum_delete_references_response(input),
        0x020f => parse_service_enum_browse_request(input),
        0x0212 => parse_service_enum_browse_response(input),
        0x0215 => parse_service_enum_browse_next_request(input),
        0x0218 => parse_service_enum_browse_next_response(input),
        0x022a => parse_service_enum_translate_browse_paths_to_node_ids_request(input),
        0x022d => parse_service_enum_translate_browse_paths_to_node_ids_response(input),
        0x0230 => parse_service_enum_register_nodes_request(input),
        0x0233 => parse_service_enum_register_nodes_response(input),
        0x0236 => parse_service_enum_unregister_nodes_request(input),
        0x0239 => parse_service_enum_unregister_nodes_response(input),
        0x0267 => parse_service_enum_query_first_request(input),
        0x026a => parse_service_enum_query_first_response(input),
        0x026d => parse_service_enum_query_next_request(input),
        0x0270 => parse_service_enum_query_next_response(input),
        0x0277 => parse_service_enum_read_request(input),
        0x027a => parse_service_enum_read_response(input),
        0x0298 => parse_service_enum_history_read_request(input),
        0x029b => parse_service_enum_history_read_response(input),
        0x02a1 => parse_service_enum_write_request(input),
        0x02a4 => parse_service_enum_write_response(input),
        0x02bc => parse_service_enum_history_update_request(input),
        0x02bf => parse_service_enum_history_update_response(input),
        0x02c8 => parse_service_enum_call_request(input),
        0x02cb => parse_service_enum_call_response(input),
        0x02ef => parse_service_enum_create_monitored_items_request(input),
        0x02f2 => parse_service_enum_create_monitored_items_response(input),
        0x02fb => parse_service_enum_modify_monitored_items_request(input),
        0x02fe => parse_service_enum_modify_monitored_items_response(input),
        0x0301 => parse_service_enum_set_monitoring_mode_request(input),
        0x0304 => parse_service_enum_set_monitoring_mode_response(input),
        0x0307 => parse_service_enum_set_triggering_request(input),
        0x030a => parse_service_enum_set_triggering_response(input),
        0x030d => parse_service_enum_delete_monitored_items_request(input),
        0x0310 => parse_service_enum_delete_monitored_items_response(input),
        0x0313 => parse_service_enum_create_subscription_request(input),
        0x0316 => parse_service_enum_create_subscription_response(input),
        0x0319 => parse_service_enum_modify_subscription_request(input),
        0x031c => parse_service_enum_modify_subscription_response(input),
        0x031f => parse_service_enum_set_publishing_mode_request(input),
        0x0322 => parse_service_enum_set_publishing_mode_response(input),
        0x033a => parse_service_enum_publish_request(input),
        0x033d => parse_service_enum_publish_response(input),
        0x0340 => parse_service_enum_republish_request(input),
        0x0343 => parse_service_enum_republish_response(input),
        0x0349 => parse_service_enum_transfer_subscriptions_request(input),
        0x034c => parse_service_enum_transfer_subscriptions_response(input),
        0x034f => parse_service_enum_delete_subscriptions_request(input),
        0x0352 => parse_service_enum_delete_subscriptions_response(input),
        0x019a => parse_service_enum_test_stack_request(input),
        0x019d => parse_service_enum_test_stack_response(input),
        0x01a0 => parse_service_enum_test_stack_ex_request(input),
        0x01a3 => parse_service_enum_test_stack_ex_response(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, service_enum))
}

pub fn parse_service_nodeid_info(
    input: &[u8],
    service_nodeid_encodingmask: u8,
) -> IResult<&[u8], ServiceNodeidInfo> {
    let (input, service_nodeid_info) = match service_nodeid_encodingmask {
        0x0 => {
            let (input, service_nodeid_numeric) = u8(input)?;
            let (input, service_enum) = parse_service_enum(input, service_nodeid_numeric as u32)?;
            Ok((
                input,
                ServiceNodeidInfo::TB {
                    service_nodeid_numeric,
                    service_enum,
                },
            ))
        }
        0x01 => {
            let (input, service_nodeid_namespace) = u8(input)?;
            let (input, service_nodeid_numeric) = le_u16(input)?;
            let (input, service_enum) = parse_service_enum(input, service_nodeid_numeric as u32)?;
            Ok((
                input,
                ServiceNodeidInfo::FB {
                    service_nodeid_namespace,
                    service_nodeid_numeric,
                    service_enum,
                },
            ))
        }
        0x02 => {
            let (input, service_nodeid_namespace) = le_u16(input)?;
            let (input, service_nodeid_numeric) = le_u32(input)?;
            let (input, service_enum) = parse_service_enum(input, service_nodeid_numeric)?;
            Ok((
                input,
                ServiceNodeidInfo::Numeric {
                    service_nodeid_namespace,
                    service_nodeid_numeric,
                    service_enum,
                },
            ))
        }
        0x03 => Ok((input, ServiceNodeidInfo::String {})),
        0x04 => Ok((input, ServiceNodeidInfo::Guid {})),
        0x05 => Ok((input, ServiceNodeidInfo::Opaque {})),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, service_nodeid_info))
}

pub fn parse_msg_variant_info(input: &[u8], chunk_type: u8) -> IResult<&[u8], MsgVariantInfo> {
    let (input, msg_variant_info) = match chunk_type {
        0x41 => {
            let (input, _error_len) = le_u32(input)?;
            let mut _error_len = _error_len;
            if _error_len == 0xffffffff {
                _error_len = 0;
            }
            let (input, _error) = take(_error_len as usize)(input)?;
            let error = match std::str::from_utf8(_error) {
                Ok(o) => o,
                Err(_) => {
                    return Err(nom::Err::Error(nom::error::Error::new(
                        input,
                        nom::error::ErrorKind::Verify,
                    )))
                }
            };
            let (input, _reason_len) = le_u32(input)?;
            let mut _reason_len = _reason_len;
            if _reason_len == 0xffffffff {
                _reason_len = 0;
            }
            let (input, _reason) = take(_reason_len as usize)(input)?;
            let reason = match std::str::from_utf8(_reason) {
                Ok(o) => o,
                Err(_) => {
                    return Err(nom::Err::Error(nom::error::Error::new(
                        input,
                        nom::error::ErrorKind::Verify,
                    )))
                }
            };
            Ok((input, MsgVariantInfo::Abort { error, reason }))
        }
        _ => {
            let (input, service_nodeid_encodingmask) = u8(input)?;
            let (input, service_nodeid_info) =
                parse_service_nodeid_info(input, service_nodeid_encodingmask)?;
            Ok((
                input,
                MsgVariantInfo::Service {
                    service_nodeid_encodingmask,
                    service_nodeid_info,
                },
            ))
        }
    }?;
    Ok((input, msg_variant_info))
}

pub fn parse_message_type_enum(input: &[u8], message_type: u32) -> IResult<&[u8], MessageTypeEnum> {
    let (input, message_type_enum) = match message_type {
        0x48454c => {
            let (input, chunk_type) = u8(input)?;
            let (input, transport_size) = le_u32(input)?;
            let (input, version) = le_u32(input)?;
            let (input, receive_buffer_size) = le_u32(input)?;
            let (input, send_buffer_size) = le_u32(input)?;
            let (input, max_message_size) = le_u32(input)?;
            let (input, max_chunk_count) = le_u32(input)?;
            let (input, _endpoint_url_len) = le_u32(input)?;
            let mut _endpoint_url_len = _endpoint_url_len;
            if _endpoint_url_len == 0xffffffff {
                _endpoint_url_len = 0;
            }
            let (input, _endpoint_url) = take(_endpoint_url_len as usize)(input)?;
            let endpoint_url = match std::str::from_utf8(_endpoint_url) {
                Ok(o) => o,
                Err(_) => {
                    return Err(nom::Err::Error(nom::error::Error::new(
                        input,
                        nom::error::ErrorKind::Verify,
                    )))
                }
            };
            Ok((
                input,
                MessageTypeEnum::Hello {
                    chunk_type,
                    transport_size,
                    version,
                    receive_buffer_size,
                    send_buffer_size,
                    max_message_size,
                    max_chunk_count,
                    endpoint_url,
                },
            ))
        }
        0x41434b => {
            let (input, chunk_type) = u8(input)?;
            let (input, transport_size) = le_u32(input)?;
            let (input, version) = le_u32(input)?;
            let (input, receive_buffer_size) = le_u32(input)?;
            let (input, send_buffer_size) = le_u32(input)?;
            let (input, max_message_size) = le_u32(input)?;
            let (input, max_chunk_count) = le_u32(input)?;
            Ok((
                input,
                MessageTypeEnum::Acknowledge {
                    chunk_type,
                    transport_size,
                    version,
                    receive_buffer_size,
                    send_buffer_size,
                    max_message_size,
                    max_chunk_count,
                },
            ))
        }
        0x455252 => {
            let (input, chunk_type) = u8(input)?;
            let (input, transport_size) = le_u32(input)?;
            let (input, error) = le_u32(input)?;
            let (input, reason) = le_u32(input)?;
            Ok((
                input,
                MessageTypeEnum::Error {
                    chunk_type,
                    transport_size,
                    error,
                    reason,
                },
            ))
        }
        0x524845 => {
            let (input, chunk_type) = u8(input)?;
            let (input, transport_size) = le_u32(input)?;
            let (input, _suri_len) = le_u32(input)?;
            let mut _suri_len = _suri_len;
            if _suri_len == 0xffffffff {
                _suri_len = 0;
            }
            let (input, _suri) = take(_suri_len as usize)(input)?;
            let suri = match std::str::from_utf8(_suri) {
                Ok(o) => o,
                Err(_) => {
                    return Err(nom::Err::Error(nom::error::Error::new(
                        input,
                        nom::error::ErrorKind::Verify,
                    )))
                }
            };
            let (input, _endpoint_url_len) = le_u32(input)?;
            let mut _endpoint_url_len = _endpoint_url_len;
            if _endpoint_url_len == 0xffffffff {
                _endpoint_url_len = 0;
            }
            let (input, _endpoint_url) = take(_endpoint_url_len as usize)(input)?;
            let endpoint_url = match std::str::from_utf8(_endpoint_url) {
                Ok(o) => o,
                Err(_) => {
                    return Err(nom::Err::Error(nom::error::Error::new(
                        input,
                        nom::error::ErrorKind::Verify,
                    )))
                }
            };
            Ok((
                input,
                MessageTypeEnum::ReverseHello {
                    chunk_type,
                    transport_size,
                    suri,
                    endpoint_url,
                },
            ))
        }
        0x4d5347 => {
            let (input, chunk_type) = u8(input)?;
            let (input, transport_size) = le_u32(input)?;
            let (input, secure_channel_id) = le_u32(input)?;
            let (input, security_token_id) = le_u32(input)?;
            let (input, security_sequence_number) = le_u32(input)?;
            let (input, security_request_id) = le_u32(input)?;
            let (input, msg_variant_info) = parse_msg_variant_info(input, chunk_type)?;
            Ok((
                input,
                MessageTypeEnum::Message {
                    chunk_type,
                    transport_size,
                    secure_channel_id,
                    security_token_id,
                    security_sequence_number,
                    security_request_id,
                    msg_variant_info,
                },
            ))
        }
        0x4f504e => Ok((input, MessageTypeEnum::OpenSecureChannel {})),
        0x434c4f => Ok((input, MessageTypeEnum::CloseSecureChannel {})),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, message_type_enum))
}
