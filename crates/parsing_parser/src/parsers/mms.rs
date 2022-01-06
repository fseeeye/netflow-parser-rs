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
use tracing::{debug, error, info, warn};

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
pub struct MmsHeader<'a> {
    pub osi_protocol_stack: OsiProtocolStack<'a>,
    pub mms_pdu: MmsPdu<'a>,
}

pub fn parse_mms_header(input: &[u8]) -> IResult<&[u8], MmsHeader> {
    let (input, osi_protocol_stack) = parse_osi_protocol_stack(input)?;
    let (input, mms_pdu) = parse_mms_pdu(input)?;
    Ok((
        input,
        MmsHeader {
            osi_protocol_stack,
            mms_pdu,
        },
    ))
}

pub fn parse_mms_layer<'a>(
    input: &'a [u8],
    link_layer: LinkLayer,
    network_layer: NetworkLayer<'a>,
    transport_layer: TransportLayer<'a>,
    options: &QuinPacketOptions,
) -> QuinPacket<'a> {
    let current_prototype = ProtocolType::Application(ApplicationProtocol::Mms);

    let (input, mms_header) = match parse_mms_header(input) {
        Ok(o) => o,
        Err(e) => {
            error!(
                target: "PARSER(mms::parse_mms_layer)",
                error = ?e
            );
            return QuinPacket::L4(L4Packet {
                link_layer,
                network_layer,
                transport_layer,
                error: Some(ParseError::ParsingHeader),
                remain: input,
            });
        }
    };

    if Some(current_prototype) == options.stop {
        let application_layer = ApplicationLayer::Mms(mms_header);
        return QuinPacket::L5(L5Packet {
            link_layer,
            network_layer,
            transport_layer,
            application_layer,
            error: None,
            remain: input,
        });
    };

    let application_layer = ApplicationLayer::Mms(mms_header);
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
pub struct SimpleItem<'a> {
    pub data: &'a [u8],
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SimpleU8Data {
    pub data: u8,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OsiSesConnectAcceptItem {
    pub connect_accept_item_parameter_type: u8,
    pub connect_accept_item_parameter_length: u8,
    pub porocol_parameter_type: u8,
    pub porocol_parameter_length: u8,
    pub porocol_flag: u8,
    pub version_number_parameter_type: u8,
    pub version_number_parameter_length: u8,
    pub version_number_parameter_flag: u8,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OsiSesSessionRequirement {
    pub session_requirement_parameter_type: u8,
    pub session_requirement_parameter_length: u8,
    pub session_requirement_flag: u16,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OsiSesCallingSessionSelector {
    pub calling_session_selector_parameter_type: u8,
    pub calling_session_selector_parameter_length: u8,
    pub calling_session_selector_value: u16,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OsiSesCalledSessionSelector {
    pub called_session_selector_parameter_type: u8,
    pub called_session_selector_parameter_length: u8,
    pub called_session_selector_value: u16,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OsiSesSessionUserData {
    pub session_user_data_parameter_type: u8,
    pub session_user_data_parameter_length: u8,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OsiSesConnectRequest {
    pub connect_accept_item: OsiSesConnectAcceptItem,
    pub session_requirement: OsiSesSessionRequirement,
    pub calling_session_selector: OsiSesCallingSessionSelector,
    pub called_session_selector: OsiSesCalledSessionSelector,
    pub session_user_data: OsiSesSessionUserData,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OsiPresUserData {
    pub presentation_context_indentifier: SimpleU8Data,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NormalModeParametersCpWithProtocolVersion<'a> {
    pub protocol_version: SimpleItem<'a>,
    pub calling_presentation_selector: SimpleItem<'a>,
    pub called_presentation_selector: SimpleItem<'a>,
    pub presentation_context_definition_list: SimpleItem<'a>,
    pub presentation_requirements: SimpleItem<'a>,
    pub user_data: OsiPresUserData,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NormalModeParametersCpaWithProtocolVersion<'a> {
    pub protocol_version: SimpleItem<'a>,
    pub responding_presentation_selector: SimpleItem<'a>,
    pub presentation_context_definition_result_list: SimpleItem<'a>,
    pub user_data: OsiPresUserData,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OsiPresPduNormalModeParametersCp<'a> {
    pub calling_presentation_selector: SimpleItem<'a>,
    pub called_presentation_selector: SimpleItem<'a>,
    pub presentation_context_definition_list: SimpleItem<'a>,
    pub presentation_requirements: SimpleItem<'a>,
    pub user_data: OsiPresUserData,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OsiPresPduNormalModeParametersCpa<'a> {
    pub responding_presentation_selector: SimpleItem<'a>,
    pub presentation_context_definition_result_list: SimpleItem<'a>,
    pub user_data: OsiPresUserData,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum OsiPresPduNormalModeParametersCpChoice<'a> {
    NormalModeParametersCpWithProtocolVersionChoice {
        normal_mode_parameters_cp_with_protocol_version:
            NormalModeParametersCpWithProtocolVersion<'a>,
    },
    NormalModeParametersCpChoice {
        osi_pres_pdu_normal_mode_parameters_cp: OsiPresPduNormalModeParametersCp<'a>,
    },
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum OsiPresPduNormalModeParametersCpaChoice<'a> {
    NormalModeParametersCpaWithProtocolVersionChoice {
        normal_mode_parameters_cpa_with_protocol_version:
            NormalModeParametersCpaWithProtocolVersion<'a>,
    },
    NormalModeParametersCpaChoice {
        osi_pres_pdu_normal_mode_parameters_cpa: OsiPresPduNormalModeParametersCpa<'a>,
    },
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OsiPresCp<'a> {
    pub pres_cp_mode_selector: SimpleItem<'a>,
    pub normal_mode_parameters: OsiPresPduNormalModeParametersCpChoice<'a>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OsiPresCpa<'a> {
    pub pres_cp_mode_selector: SimpleItem<'a>,
    pub normal_mode_parameters: OsiPresPduNormalModeParametersCpaChoice<'a>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OsiAcseAarq<'a> {
    pub protocol_version: SimpleItem<'a>,
    pub aso_context_name: SimpleItem<'a>,
    pub called_ap_title: SimpleItem<'a>,
    pub called_ae_qualifier: SimpleItem<'a>,
    pub direct_ref: SimpleItem<'a>,
    pub indirect_ref: SimpleItem<'a>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OsiAcseAare<'a> {
    pub protocol_version: SimpleItem<'a>,
    pub aso_context_name: SimpleItem<'a>,
    pub result: SimpleItem<'a>,
    pub result_source_diagnostic: SimpleItem<'a>,
    pub responsding_ap_title: SimpleItem<'a>,
    pub responsding_ae_qualifier: SimpleItem<'a>,
    pub user_information: SimpleItem<'a>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum OsiSesChoice<'a> {
    Request {
        connect_accept: OsiSesConnectRequest,
        pres_cp: OsiPresCp<'a>,
        acse: OsiAcseAarq<'a>,
    },
    Response {
        accept: OsiSesConnectRequest,
        pres_cpa: OsiPresCpa<'a>,
        acse: OsiAcseAare<'a>,
    },
    GiveTokens {
        ses2_type: u8,
        ses2_len: u8,
        pres_cpa: OsiPresUserData,
    },
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OsiProtocolStack<'a> {
    pub ses_type: u8,
    pub ses_len: u8,
    pub ses: OsiSesChoice<'a>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ObjectClass<'a> {
    NamedVariable { named_variable: SimpleItem<'a> },
    ScatteredAccess { scattered_access: SimpleItem<'a> },
    NamedVariableList { named_variable_list: SimpleItem<'a> },
    NamedType { named_type: SimpleItem<'a> },
    Semaphore { semaphore: SimpleItem<'a> },
    EventCondition { event_condition: SimpleItem<'a> },
    EventAction { event_action: SimpleItem<'a> },
    EventEnrollment { event_enrollment: SimpleItem<'a> },
    Journal { journal: SimpleItem<'a> },
    Domain { domain: SimpleItem<'a> },
    ProgramInvocation { program_invocation: SimpleItem<'a> },
    OperatorStation { operator_station: SimpleItem<'a> },
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ObjectScope<'a> {
    ObjectScopeVmd {
        object_scope_vmd: &'a [u8],
    },
    ObjectScopeDomain {
        object_scope_domain_id: &'a [u8],
        object_scope_item_id: &'a [u8],
    },
    ObjectScopeAaSpecific {
        object_scope_aa_specific: &'a [u8],
    },
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ObjectName<'a> {
    ObjectNameVmd {
        object_name_vmd: &'a [u8],
    },
    ObjectNameDomain {
        object_name_domain_id: &'a [u8],
        object_name_item_id: &'a [u8],
    },
    ObjectNameAaSpecific {
        object_name_aa_specific: &'a [u8],
    },
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum VariableSpecification<'a> {
    Name { object_name: ObjectName<'a> },
    Others { value: &'a [u8] },
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VariableSpecificationStruct<'a> {
    pub variable_specification: VariableSpecification<'a>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ListOfVariableSpecification<'a> {
    pub lovs: Vec<VariableSpecificationStruct<'a>>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DataAccessError {
    ObjectInvalidated {
        object_invalidated: SimpleU8Data,
    },
    HardwareFault {
        hardware_fault: SimpleU8Data,
    },
    TemporarilyUnavailable {
        temporarily_unavailable: SimpleU8Data,
    },
    ObjectAccessDenied {
        object_access_denied: SimpleU8Data,
    },
    ObjectUndefined {
        object_undefined: SimpleU8Data,
    },
    InvalidAddress {
        invalid_address: SimpleU8Data,
    },
    TypeUnsupported {
        type_unsupported: SimpleU8Data,
    },
    TypeInconsistent {
        type_inconsistent: SimpleU8Data,
    },
    ObjectAttributeInconsistent {
        object_attribute_inconsistent: SimpleU8Data,
    },
    ObjectAccessUnsupported {
        object_access_unsupported: SimpleU8Data,
    },
    ObjectNonExistent {
        object_non_existent: SimpleU8Data,
    },
    ObjectValueInvalid {
        object_value_invalid: SimpleU8Data,
    },
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AccessResult<'a> {
    AccessResultFailure { data_access_error: DataAccessError },
    AccessResultSuccess { data: SimpleItem<'a> },
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AccessResultStruct<'a> {
    pub access_result: AccessResult<'a>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ListOfAccessResult<'a> {
    pub loar: Vec<AccessResultStruct<'a>>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ListOfIdentifier<'a> {
    pub loar: Vec<&'a [u8]>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct InitDetailRequest<'a> {
    pub proposed_version_number: SimpleItem<'a>,
    pub proposed_parameter_cbb: SimpleItem<'a>,
    pub service_supported_calling: SimpleItem<'a>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct InitDetailResponse<'a> {
    pub proposed_version_number: SimpleItem<'a>,
    pub proposed_parameter_cbb: SimpleItem<'a>,
    pub service_supported_called: SimpleItem<'a>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct InvokeId {
    pub invoke_id: u8,
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum VariableAccessSpecificationChoice<'a> {
    ListOfVariable {
        res: ListOfVariableSpecification<'a>,
    },
    VaribaleListName {
        object_name: ObjectName<'a>,
    },
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ReadRequestChoice<'a> {
    ReadRequestChoiceDefault {
        variable_access_specification_choice: VariableAccessSpecificationChoice<'a>,
    },
    ReadRequestChoiceOtherwise {
        specification_with_result: u8,
        variable_access_specification_choice: VariableAccessSpecificationChoice<'a>,
    },
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ReadResponseChoice<'a> {
    ReadResponseChoiceNone {},
    ReadResponseChoiceWithData {
        list_of_access_result: ListOfAccessResult<'a>,
    },
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum WriteResponseChoice {
    WriteResponseChoiceFailure { data_access_error: DataAccessError },
    WriteResponseChoiceSuccess {},
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ConfirmedServiceRequestChoice<'a> {
    GetNameListRequest {
        object_class: ObjectClass<'a>,
        object_scope: ObjectScope<'a>,
    },
    IdentifyRequest {},
    ReadRequest {
        read_request_choice: ReadRequestChoice<'a>,
    },
    WriteRequest {
        variable_access_specification_choice: VariableAccessSpecificationChoice<'a>,
        lod: Vec<SimpleItem<'a>>,
    },
    GetNamedVariableListAttributesRequest {
        object_name: ObjectName<'a>,
    },
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ConfirmedServiceResponseChoice<'a> {
    GetNameListResponse {
        list_of_identifier: ListOfIdentifier<'a>,
        more_follows: u8,
    },
    IdentifyResponse {
        vendor_name: SimpleItem<'a>,
        model_name: SimpleItem<'a>,
        revision: SimpleItem<'a>,
    },
    ReadResponse {
        read_response_choice: ReadResponseChoice<'a>,
    },
    WriteResponse {
        write_response_choice: WriteResponseChoice,
    },
    GetNamedVariableListAttributesResponse {
        mms_deleteable: u8,
        list_of_variable_specification: ListOfVariableSpecification<'a>,
    },
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ConfirmedServiceResponseStruct<'a> {
    ConfirmedServiceResponseStructNone {},
    ConfirmedServiceResponseStructWithData {
        service: ConfirmedServiceResponseChoice<'a>,
    },
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum UnConfirmedChoice<'a> {
    InformationReport {
        variable_access_specification_choice: VariableAccessSpecificationChoice<'a>,
        list_of_access_result: ListOfAccessResult<'a>,
    },
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MmsPduChoice<'a> {
    ConfirmedRequest {
        invoke_id: InvokeId,
        service: ConfirmedServiceRequestChoice<'a>,
    },
    ConfirmedResponse {
        invoke_id: InvokeId,
        service: ConfirmedServiceResponseStruct<'a>,
    },
    UnConfirmed {
        service: UnConfirmedChoice<'a>,
    },
    InitiateRequest {
        local_detail_calling: SimpleItem<'a>,
        proposed_max_serv_outstanding_calling: SimpleItem<'a>,
        proposed_max_serv_outstanding_called: SimpleItem<'a>,
        proposed_data_structure_nesting_level: SimpleItem<'a>,
        init_request_detail: InitDetailRequest<'a>,
    },
    InitiateResponse {
        local_detail_called: SimpleItem<'a>,
        proposed_max_serv_outstanding_calling: SimpleItem<'a>,
        proposed_max_serv_outstanding_called: SimpleItem<'a>,
        proposed_data_structure_nesting_level: SimpleItem<'a>,
        init_response_detail: InitDetailResponse<'a>,
    },
    ConcludeRequest {},
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MmsPdu<'a> {
    pub mms_pdu_choice: MmsPduChoice<'a>,
}

pub fn parse_simple_item(input: &[u8]) -> IResult<&[u8], SimpleItem> {
    let (input, _simple_item_tl) = ber_tl(input)?;
    let (input, data) = take(_simple_item_tl.length as usize)(input)?;
    Ok((input, SimpleItem { data }))
}

pub fn parse_simple_u8_data(input: &[u8]) -> IResult<&[u8], SimpleU8Data> {
    let (input, _simple_u8_item_tl) = ber_tl(input)?;
    let (input, data) = u8(input)?;
    Ok((input, SimpleU8Data { data }))
}

pub fn parse_osi_ses_connect_accept_item(input: &[u8]) -> IResult<&[u8], OsiSesConnectAcceptItem> {
    let (input, connect_accept_item_parameter_type) = u8(input)?;
    let (input, connect_accept_item_parameter_length) = u8(input)?;
    let (input, porocol_parameter_type) = u8(input)?;
    let (input, porocol_parameter_length) = u8(input)?;
    let (input, porocol_flag) = u8(input)?;
    let (input, version_number_parameter_type) = u8(input)?;
    let (input, version_number_parameter_length) = u8(input)?;
    let (input, version_number_parameter_flag) = u8(input)?;
    Ok((
        input,
        OsiSesConnectAcceptItem {
            connect_accept_item_parameter_type,
            connect_accept_item_parameter_length,
            porocol_parameter_type,
            porocol_parameter_length,
            porocol_flag,
            version_number_parameter_type,
            version_number_parameter_length,
            version_number_parameter_flag,
        },
    ))
}

pub fn parse_osi_ses_session_requirement(input: &[u8]) -> IResult<&[u8], OsiSesSessionRequirement> {
    let (input, session_requirement_parameter_type) = u8(input)?;
    let (input, session_requirement_parameter_length) = u8(input)?;
    let (input, session_requirement_flag) = be_u16(input)?;
    Ok((
        input,
        OsiSesSessionRequirement {
            session_requirement_parameter_type,
            session_requirement_parameter_length,
            session_requirement_flag,
        },
    ))
}

pub fn parse_osi_ses_calling_session_selector(
    input: &[u8],
) -> IResult<&[u8], OsiSesCallingSessionSelector> {
    let (input, calling_session_selector_parameter_type) = u8(input)?;
    let (input, calling_session_selector_parameter_length) = u8(input)?;
    let (input, calling_session_selector_value) = be_u16(input)?;
    Ok((
        input,
        OsiSesCallingSessionSelector {
            calling_session_selector_parameter_type,
            calling_session_selector_parameter_length,
            calling_session_selector_value,
        },
    ))
}

pub fn parse_osi_ses_called_session_selector(
    input: &[u8],
) -> IResult<&[u8], OsiSesCalledSessionSelector> {
    let (input, called_session_selector_parameter_type) = u8(input)?;
    let (input, called_session_selector_parameter_length) = u8(input)?;
    let (input, called_session_selector_value) = be_u16(input)?;
    Ok((
        input,
        OsiSesCalledSessionSelector {
            called_session_selector_parameter_type,
            called_session_selector_parameter_length,
            called_session_selector_value,
        },
    ))
}

pub fn parse_osi_ses_session_user_data(input: &[u8]) -> IResult<&[u8], OsiSesSessionUserData> {
    let (input, session_user_data_parameter_type) = u8(input)?;
    let (input, session_user_data_parameter_length) = u8(input)?;
    Ok((
        input,
        OsiSesSessionUserData {
            session_user_data_parameter_type,
            session_user_data_parameter_length,
        },
    ))
}

pub fn parse_osi_ses_connect_request(input: &[u8]) -> IResult<&[u8], OsiSesConnectRequest> {
    let (input, connect_accept_item) = parse_osi_ses_connect_accept_item(input)?;
    let (input, session_requirement) = parse_osi_ses_session_requirement(input)?;
    let (input, calling_session_selector) = parse_osi_ses_calling_session_selector(input)?;
    let (input, called_session_selector) = parse_osi_ses_called_session_selector(input)?;
    let (input, session_user_data) = parse_osi_ses_session_user_data(input)?;
    Ok((
        input,
        OsiSesConnectRequest {
            connect_accept_item,
            session_requirement,
            calling_session_selector,
            called_session_selector,
            session_user_data,
        },
    ))
}

pub fn parse_osi_pres_user_data(input: &[u8]) -> IResult<&[u8], OsiPresUserData> {
    let (input, _fullt_encode_data_tl) = ber_tl(input)?;
    let (input, presentation_context_indentifier) = parse_simple_u8_data(input)?;
    let (input, _presentation_context_values_tl) = ber_tl(input)?;
    Ok((
        input,
        OsiPresUserData {
            presentation_context_indentifier,
        },
    ))
}

pub fn parse_normal_mode_parameters_cp_with_protocol_version(
    input: &[u8],
) -> IResult<&[u8], NormalModeParametersCpWithProtocolVersion> {
    let (input, protocol_version) = parse_simple_item(input)?;
    let (input, calling_presentation_selector) = parse_simple_item(input)?;
    let (input, called_presentation_selector) = parse_simple_item(input)?;
    let (input, presentation_context_definition_list) = parse_simple_item(input)?;
    let (input, presentation_requirements) = parse_simple_item(input)?;
    let (input, _user_data_tl) = ber_tl(input)?;
    let (input, user_data) = parse_osi_pres_user_data(input)?;
    Ok((
        input,
        NormalModeParametersCpWithProtocolVersion {
            protocol_version,
            calling_presentation_selector,
            called_presentation_selector,
            presentation_context_definition_list,
            presentation_requirements,
            user_data,
        },
    ))
}

pub fn parse_normal_mode_parameters_cpa_with_protocol_version(
    input: &[u8],
) -> IResult<&[u8], NormalModeParametersCpaWithProtocolVersion> {
    let (input, protocol_version) = parse_simple_item(input)?;
    let (input, responding_presentation_selector) = parse_simple_item(input)?;
    let (input, presentation_context_definition_result_list) = parse_simple_item(input)?;
    let (input, _user_data_tl) = ber_tl(input)?;
    let (input, user_data) = parse_osi_pres_user_data(input)?;
    Ok((
        input,
        NormalModeParametersCpaWithProtocolVersion {
            protocol_version,
            responding_presentation_selector,
            presentation_context_definition_result_list,
            user_data,
        },
    ))
}

pub fn parse_osi_pres_pdu_normal_mode_parameters_cp(
    input: &[u8],
) -> IResult<&[u8], OsiPresPduNormalModeParametersCp> {
    let (input, calling_presentation_selector) = parse_simple_item(input)?;
    let (input, called_presentation_selector) = parse_simple_item(input)?;
    let (input, presentation_context_definition_list) = parse_simple_item(input)?;
    let (input, presentation_requirements) = parse_simple_item(input)?;
    let (input, _user_data_tl) = ber_tl(input)?;
    let (input, user_data) = parse_osi_pres_user_data(input)?;
    Ok((
        input,
        OsiPresPduNormalModeParametersCp {
            calling_presentation_selector,
            called_presentation_selector,
            presentation_context_definition_list,
            presentation_requirements,
            user_data,
        },
    ))
}

pub fn parse_osi_pres_pdu_normal_mode_parameters_cpa(
    input: &[u8],
) -> IResult<&[u8], OsiPresPduNormalModeParametersCpa> {
    let (input, responding_presentation_selector) = parse_simple_item(input)?;
    let (input, presentation_context_definition_result_list) = parse_simple_item(input)?;
    let (input, _user_data_tl) = ber_tl(input)?;
    let (input, user_data) = parse_osi_pres_user_data(input)?;
    Ok((
        input,
        OsiPresPduNormalModeParametersCpa {
            responding_presentation_selector,
            presentation_context_definition_result_list,
            user_data,
        },
    ))
}

fn parse_osi_pres_pdu_normal_mode_parameters_cp_choice_normal_mode_parameters_cp_with_protocol_version_choice(
    input: &[u8],
) -> IResult<&[u8], OsiPresPduNormalModeParametersCpChoice> {
    let (input, normal_mode_parameters_cp_with_protocol_version) =
        parse_normal_mode_parameters_cp_with_protocol_version(input)?;
    Ok((
        input,
        OsiPresPduNormalModeParametersCpChoice::NormalModeParametersCpWithProtocolVersionChoice {
            normal_mode_parameters_cp_with_protocol_version,
        },
    ))
}

fn parse_osi_pres_pdu_normal_mode_parameters_cp_choice_normal_mode_parameters_cp_choice(
    input: &[u8],
) -> IResult<&[u8], OsiPresPduNormalModeParametersCpChoice> {
    let (input, osi_pres_pdu_normal_mode_parameters_cp) =
        parse_osi_pres_pdu_normal_mode_parameters_cp(input)?;
    Ok((
        input,
        OsiPresPduNormalModeParametersCpChoice::NormalModeParametersCpChoice {
            osi_pres_pdu_normal_mode_parameters_cp,
        },
    ))
}

pub fn parse_osi_pres_pdu_normal_mode_parameters_cp_choice(
    input: &[u8],
) -> IResult<&[u8], OsiPresPduNormalModeParametersCpChoice> {
    let (input, _tag) = peek(u8)(input)?;
    let (input, osi_pres_pdu_normal_mode_parameters_cp_choice) = match _tag {
        0x80 => parse_osi_pres_pdu_normal_mode_parameters_cp_choice_normal_mode_parameters_cp_with_protocol_version_choice(input),
        _ => parse_osi_pres_pdu_normal_mode_parameters_cp_choice_normal_mode_parameters_cp_choice(input),
    }?;
    Ok((input, osi_pres_pdu_normal_mode_parameters_cp_choice))
}

fn parse_osi_pres_pdu_normal_mode_parameters_cpa_choice_normal_mode_parameters_cpa_with_protocol_version_choice(
    input: &[u8],
) -> IResult<&[u8], OsiPresPduNormalModeParametersCpaChoice> {
    let (input, normal_mode_parameters_cpa_with_protocol_version) =
        parse_normal_mode_parameters_cpa_with_protocol_version(input)?;
    Ok((
        input,
        OsiPresPduNormalModeParametersCpaChoice::NormalModeParametersCpaWithProtocolVersionChoice {
            normal_mode_parameters_cpa_with_protocol_version,
        },
    ))
}

fn parse_osi_pres_pdu_normal_mode_parameters_cpa_choice_normal_mode_parameters_cpa_choice(
    input: &[u8],
) -> IResult<&[u8], OsiPresPduNormalModeParametersCpaChoice> {
    let (input, osi_pres_pdu_normal_mode_parameters_cpa) =
        parse_osi_pres_pdu_normal_mode_parameters_cpa(input)?;
    Ok((
        input,
        OsiPresPduNormalModeParametersCpaChoice::NormalModeParametersCpaChoice {
            osi_pres_pdu_normal_mode_parameters_cpa,
        },
    ))
}

pub fn parse_osi_pres_pdu_normal_mode_parameters_cpa_choice(
    input: &[u8],
) -> IResult<&[u8], OsiPresPduNormalModeParametersCpaChoice> {
    let (input, _tag) = peek(u8)(input)?;
    let (input, osi_pres_pdu_normal_mode_parameters_cpa_choice) = match _tag {
        0x80 => parse_osi_pres_pdu_normal_mode_parameters_cpa_choice_normal_mode_parameters_cpa_with_protocol_version_choice(input),
        _ => parse_osi_pres_pdu_normal_mode_parameters_cpa_choice_normal_mode_parameters_cpa_choice(input),
    }?;
    Ok((input, osi_pres_pdu_normal_mode_parameters_cpa_choice))
}

pub fn parse_osi_pres_cp(input: &[u8]) -> IResult<&[u8], OsiPresCp> {
    let (input, _pres_tl) = ber_tl(input)?;
    let (input, _pres_cp_tl) = ber_tl(input)?;
    let (input, pres_cp_mode_selector) = parse_simple_item(input)?;
    let (input, _normal_mode_parameters_tl) = ber_tl(input)?;
    let (input, normal_mode_parameters) =
        parse_osi_pres_pdu_normal_mode_parameters_cp_choice(input)?;
    Ok((
        input,
        OsiPresCp {
            pres_cp_mode_selector,
            normal_mode_parameters,
        },
    ))
}

pub fn parse_osi_pres_cpa(input: &[u8]) -> IResult<&[u8], OsiPresCpa> {
    let (input, _pres_tl) = ber_tl(input)?;
    let (input, _pres_cpa_tl) = ber_tl(input)?;
    let (input, pres_cp_mode_selector) = parse_simple_item(input)?;
    let (input, _normal_mode_parameters_tl) = ber_tl(input)?;
    let (input, normal_mode_parameters) =
        parse_osi_pres_pdu_normal_mode_parameters_cpa_choice(input)?;
    Ok((
        input,
        OsiPresCpa {
            pres_cp_mode_selector,
            normal_mode_parameters,
        },
    ))
}

pub fn parse_osi_acse_aarq(input: &[u8]) -> IResult<&[u8], OsiAcseAarq> {
    let (input, _acse_aarq_tl) = ber_tl(input)?;
    let (input, protocol_version) = parse_simple_item(input)?;
    let (input, aso_context_name) = parse_simple_item(input)?;
    let (input, called_ap_title) = parse_simple_item(input)?;
    let (input, called_ae_qualifier) = parse_simple_item(input)?;
    let (_, _tag) = peek(u8)(input)?;
    let mut input = input;
    if _tag.bitand(0xf0) == 0xa0 {
        // parse calling ap title / calling ae qulifier
        (input, ..) = parse_simple_item(input)?;
        (input, ..) = parse_simple_item(input)?;
    }
    let (input, _user_information_tl) = ber_tl(input)?;
    let (input, _association_data_tl) = ber_tl(input)?;
    let (input, direct_ref) = parse_simple_item(input)?;
    let (input, indirect_ref) = parse_simple_item(input)?;
    let (input, _encoding_tl) = ber_tl(input)?;
    Ok((
        input,
        OsiAcseAarq {
            protocol_version,
            aso_context_name,
            called_ap_title,
            called_ae_qualifier,
            direct_ref,
            indirect_ref,
        },
    ))
}

pub fn parse_osi_acse_aare(input: &[u8]) -> IResult<&[u8], OsiAcseAare> {
    let (input, _acse_aare_tl) = ber_tl(input)?;
    let (input, protocol_version) = parse_simple_item(input)?;
    let (input, aso_context_name) = parse_simple_item(input)?;
    let (input, result) = parse_simple_item(input)?;
    let (input, result_source_diagnostic) = parse_simple_item(input)?;
    let (input, responsding_ap_title) = parse_simple_item(input)?;
    let (input, responsding_ae_qualifier) = parse_simple_item(input)?;
    let (input, user_information) = parse_simple_item(input)?;
    Ok((
        input,
        OsiAcseAare {
            protocol_version,
            aso_context_name,
            result,
            result_source_diagnostic,
            responsding_ap_title,
            responsding_ae_qualifier,
            user_information,
        },
    ))
}

fn parse_osi_ses_choice_request(input: &[u8]) -> IResult<&[u8], OsiSesChoice> {
    let (input, connect_accept) = parse_osi_ses_connect_request(input)?;
    let (input, pres_cp) = parse_osi_pres_cp(input)?;
    let (input, acse) = parse_osi_acse_aarq(input)?;
    Ok((
        input,
        OsiSesChoice::Request {
            connect_accept,
            pres_cp,
            acse,
        },
    ))
}

fn parse_osi_ses_choice_response(input: &[u8]) -> IResult<&[u8], OsiSesChoice> {
    let (input, accept) = parse_osi_ses_connect_request(input)?;
    let (input, pres_cpa) = parse_osi_pres_cpa(input)?;
    let (input, acse) = parse_osi_acse_aare(input)?;
    Ok((
        input,
        OsiSesChoice::Response {
            accept,
            pres_cpa,
            acse,
        },
    ))
}

fn parse_osi_ses_choice_give_tokens(input: &[u8]) -> IResult<&[u8], OsiSesChoice> {
    let (input, ses2_type) = u8(input)?;
    let (input, ses2_len) = u8(input)?;
    let (input, _pres_cpa_tl) = ber_tl(input)?;
    let (input, pres_cpa) = parse_osi_pres_user_data(input)?;
    Ok((
        input,
        OsiSesChoice::GiveTokens {
            ses2_type,
            ses2_len,
            pres_cpa,
        },
    ))
}

pub fn parse_osi_ses_choice(input: &[u8], ses_type: u8) -> IResult<&[u8], OsiSesChoice> {
    let (input, osi_ses_choice) = match ses_type {
        0x0d => parse_osi_ses_choice_request(input),
        0x0e => parse_osi_ses_choice_response(input),
        0x01 => parse_osi_ses_choice_give_tokens(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, osi_ses_choice))
}

pub fn parse_osi_protocol_stack(input: &[u8]) -> IResult<&[u8], OsiProtocolStack> {
    let (input, ses_type) = u8(input)?;
    let (input, ses_len) = u8(input)?;
    let (input, ses) = parse_osi_ses_choice(input, ses_type)?;
    Ok((
        input,
        OsiProtocolStack {
            ses_type,
            ses_len,
            ses,
        },
    ))
}

fn parse_object_class_named_variable(input: &[u8]) -> IResult<&[u8], ObjectClass> {
    let (input, named_variable) = parse_simple_item(input)?;
    Ok((input, ObjectClass::NamedVariable { named_variable }))
}

fn parse_object_class_scattered_access(input: &[u8]) -> IResult<&[u8], ObjectClass> {
    let (input, scattered_access) = parse_simple_item(input)?;
    Ok((input, ObjectClass::ScatteredAccess { scattered_access }))
}

fn parse_object_class_named_variable_list(input: &[u8]) -> IResult<&[u8], ObjectClass> {
    let (input, named_variable_list) = parse_simple_item(input)?;
    Ok((
        input,
        ObjectClass::NamedVariableList {
            named_variable_list,
        },
    ))
}

fn parse_object_class_named_type(input: &[u8]) -> IResult<&[u8], ObjectClass> {
    let (input, named_type) = parse_simple_item(input)?;
    Ok((input, ObjectClass::NamedType { named_type }))
}

fn parse_object_class_semaphore(input: &[u8]) -> IResult<&[u8], ObjectClass> {
    let (input, semaphore) = parse_simple_item(input)?;
    Ok((input, ObjectClass::Semaphore { semaphore }))
}

fn parse_object_class_event_condition(input: &[u8]) -> IResult<&[u8], ObjectClass> {
    let (input, event_condition) = parse_simple_item(input)?;
    Ok((input, ObjectClass::EventCondition { event_condition }))
}

fn parse_object_class_event_action(input: &[u8]) -> IResult<&[u8], ObjectClass> {
    let (input, event_action) = parse_simple_item(input)?;
    Ok((input, ObjectClass::EventAction { event_action }))
}

fn parse_object_class_event_enrollment(input: &[u8]) -> IResult<&[u8], ObjectClass> {
    let (input, event_enrollment) = parse_simple_item(input)?;
    Ok((input, ObjectClass::EventEnrollment { event_enrollment }))
}

fn parse_object_class_journal(input: &[u8]) -> IResult<&[u8], ObjectClass> {
    let (input, journal) = parse_simple_item(input)?;
    Ok((input, ObjectClass::Journal { journal }))
}

fn parse_object_class_domain(input: &[u8]) -> IResult<&[u8], ObjectClass> {
    let (input, domain) = parse_simple_item(input)?;
    Ok((input, ObjectClass::Domain { domain }))
}

fn parse_object_class_program_invocation(input: &[u8]) -> IResult<&[u8], ObjectClass> {
    let (input, program_invocation) = parse_simple_item(input)?;
    Ok((input, ObjectClass::ProgramInvocation { program_invocation }))
}

fn parse_object_class_operator_station(input: &[u8]) -> IResult<&[u8], ObjectClass> {
    let (input, operator_station) = parse_simple_item(input)?;
    Ok((input, ObjectClass::OperatorStation { operator_station }))
}

pub fn parse_object_class(input: &[u8], _object_class_tl_tag: u8) -> IResult<&[u8], ObjectClass> {
    let (input, object_class) = match _object_class_tl_tag.bitand(0x1f) {
        0x0 => parse_object_class_named_variable(input),
        0x01 => parse_object_class_scattered_access(input),
        0x02 => parse_object_class_named_variable_list(input),
        0x03 => parse_object_class_named_type(input),
        0x04 => parse_object_class_semaphore(input),
        0x05 => parse_object_class_event_condition(input),
        0x06 => parse_object_class_event_action(input),
        0x07 => parse_object_class_event_enrollment(input),
        0x08 => parse_object_class_journal(input),
        0x09 => parse_object_class_domain(input),
        0x0a => parse_object_class_program_invocation(input),
        0x0b => parse_object_class_operator_station(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, object_class))
}

fn parse_object_scope_object_scope_vmd(input: &[u8]) -> IResult<&[u8], ObjectScope> {
    let (input, object_scope_vmd) = take(input.len() as usize)(input)?;
    Ok((input, ObjectScope::ObjectScopeVmd { object_scope_vmd }))
}

fn parse_object_scope_object_scope_domain(input: &[u8]) -> IResult<&[u8], ObjectScope> {
    let (input, object_scope_domain_id) = take(input.len() as usize)(input)?;
    let (input, object_scope_item_id) = take(input.len() as usize)(input)?;
    Ok((
        input,
        ObjectScope::ObjectScopeDomain {
            object_scope_domain_id,
            object_scope_item_id,
        },
    ))
}

fn parse_object_scope_object_scope_aa_specific(input: &[u8]) -> IResult<&[u8], ObjectScope> {
    let (input, object_scope_aa_specific) = take(input.len() as usize)(input)?;
    Ok((
        input,
        ObjectScope::ObjectScopeAaSpecific {
            object_scope_aa_specific,
        },
    ))
}

pub fn parse_object_scope(input: &[u8], _object_scope_tl_tag: u8) -> IResult<&[u8], ObjectScope> {
    let (input, object_scope) = match _object_scope_tl_tag.bitand(0x1f) {
        0x0 => parse_object_scope_object_scope_vmd(input),
        0x01 => parse_object_scope_object_scope_domain(input),
        0x02 => parse_object_scope_object_scope_aa_specific(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, object_scope))
}

fn parse_object_name_object_name_vmd(input: &[u8]) -> IResult<&[u8], ObjectName> {
    let (input, object_name_vmd) = take(input.len() as usize)(input)?;
    Ok((input, ObjectName::ObjectNameVmd { object_name_vmd }))
}

fn parse_object_name_object_name_domain(input: &[u8]) -> IResult<&[u8], ObjectName> {
    let (input, object_name_domain_id) = take(input.len() as usize)(input)?;
    let (input, object_name_item_id) = take(input.len() as usize)(input)?;
    Ok((
        input,
        ObjectName::ObjectNameDomain {
            object_name_domain_id,
            object_name_item_id,
        },
    ))
}

fn parse_object_name_object_name_aa_specific(input: &[u8]) -> IResult<&[u8], ObjectName> {
    let (input, object_name_aa_specific) = take(input.len() as usize)(input)?;
    Ok((
        input,
        ObjectName::ObjectNameAaSpecific {
            object_name_aa_specific,
        },
    ))
}

pub fn parse_object_name(input: &[u8], _object_name_tl_tag: u8) -> IResult<&[u8], ObjectName> {
    let (input, object_name) = match _object_name_tl_tag.bitand(0x1f) {
        0x0 => parse_object_name_object_name_vmd(input),
        0x01 => parse_object_name_object_name_domain(input),
        0x02 => parse_object_name_object_name_aa_specific(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, object_name))
}

fn parse_variable_specification_name(input: &[u8]) -> IResult<&[u8], VariableSpecification> {
    let (input, _object_name_tl) = ber_tl(input)?;
    let (input, object_name) = parse_object_name(input, _object_name_tl.tag)?;
    Ok((input, VariableSpecification::Name { object_name }))
}

fn parse_variable_specification_others(input: &[u8]) -> IResult<&[u8], VariableSpecification> {
    let (input, _variable_specification_tl) = ber_tl(input)?;
    let (input, value) = take(_variable_specification_tl.length as usize)(input)?;
    Ok((input, VariableSpecification::Others { value }))
}

pub fn parse_variable_specification(
    input: &[u8],
    _variable_specification_tl_tag: u8,
) -> IResult<&[u8], VariableSpecification> {
    let (input, variable_specification) = match _variable_specification_tl_tag.bitand(0x1f) {
        0x0 => parse_variable_specification_name(input),
        0x01 => parse_variable_specification_others(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, variable_specification))
}

pub fn parse_variable_specification_struct(
    input: &[u8],
) -> IResult<&[u8], VariableSpecificationStruct> {
    let (input, _variable_specification_tl) = ber_tl(input)?;
    let (input, variable_specification) =
        parse_variable_specification(input, _variable_specification_tl.tag)?;
    Ok((
        input,
        VariableSpecificationStruct {
            variable_specification,
        },
    ))
}

pub fn parse_list_of_variable_specification(
    input: &[u8],
) -> IResult<&[u8], ListOfVariableSpecification> {
    let (input, _lovs_tl) = ber_tl(input)?;
    /* LimitedLenVecLoopField Start */
    let mut lovs = Vec::new();
    let mut _lovs: VariableSpecificationStruct;
    let mut input = input;
    let len_flag = input.len() - _lovs_tl.length as usize;
    while input.len() > len_flag {
        (input, _lovs) = parse_variable_specification_struct(input)?;
        lovs.push(_lovs);
    }
    let input = input;
    /* LimitedLenVecLoopField End. */
    Ok((input, ListOfVariableSpecification { lovs }))
}

fn parse_data_access_error_object_invalidated(input: &[u8]) -> IResult<&[u8], DataAccessError> {
    let (input, object_invalidated) = parse_simple_u8_data(input)?;
    Ok((
        input,
        DataAccessError::ObjectInvalidated { object_invalidated },
    ))
}

fn parse_data_access_error_hardware_fault(input: &[u8]) -> IResult<&[u8], DataAccessError> {
    let (input, hardware_fault) = parse_simple_u8_data(input)?;
    Ok((input, DataAccessError::HardwareFault { hardware_fault }))
}

fn parse_data_access_error_temporarily_unavailable(
    input: &[u8],
) -> IResult<&[u8], DataAccessError> {
    let (input, temporarily_unavailable) = parse_simple_u8_data(input)?;
    Ok((
        input,
        DataAccessError::TemporarilyUnavailable {
            temporarily_unavailable,
        },
    ))
}

fn parse_data_access_error_object_access_denied(input: &[u8]) -> IResult<&[u8], DataAccessError> {
    let (input, object_access_denied) = parse_simple_u8_data(input)?;
    Ok((
        input,
        DataAccessError::ObjectAccessDenied {
            object_access_denied,
        },
    ))
}

fn parse_data_access_error_object_undefined(input: &[u8]) -> IResult<&[u8], DataAccessError> {
    let (input, object_undefined) = parse_simple_u8_data(input)?;
    Ok((input, DataAccessError::ObjectUndefined { object_undefined }))
}

fn parse_data_access_error_invalid_address(input: &[u8]) -> IResult<&[u8], DataAccessError> {
    let (input, invalid_address) = parse_simple_u8_data(input)?;
    Ok((input, DataAccessError::InvalidAddress { invalid_address }))
}

fn parse_data_access_error_type_unsupported(input: &[u8]) -> IResult<&[u8], DataAccessError> {
    let (input, type_unsupported) = parse_simple_u8_data(input)?;
    Ok((input, DataAccessError::TypeUnsupported { type_unsupported }))
}

fn parse_data_access_error_type_inconsistent(input: &[u8]) -> IResult<&[u8], DataAccessError> {
    let (input, type_inconsistent) = parse_simple_u8_data(input)?;
    Ok((
        input,
        DataAccessError::TypeInconsistent { type_inconsistent },
    ))
}

fn parse_data_access_error_object_attribute_inconsistent(
    input: &[u8],
) -> IResult<&[u8], DataAccessError> {
    let (input, object_attribute_inconsistent) = parse_simple_u8_data(input)?;
    Ok((
        input,
        DataAccessError::ObjectAttributeInconsistent {
            object_attribute_inconsistent,
        },
    ))
}

fn parse_data_access_error_object_access_unsupported(
    input: &[u8],
) -> IResult<&[u8], DataAccessError> {
    let (input, object_access_unsupported) = parse_simple_u8_data(input)?;
    Ok((
        input,
        DataAccessError::ObjectAccessUnsupported {
            object_access_unsupported,
        },
    ))
}

fn parse_data_access_error_object_non_existent(input: &[u8]) -> IResult<&[u8], DataAccessError> {
    let (input, object_non_existent) = parse_simple_u8_data(input)?;
    Ok((
        input,
        DataAccessError::ObjectNonExistent {
            object_non_existent,
        },
    ))
}

fn parse_data_access_error_object_value_invalid(input: &[u8]) -> IResult<&[u8], DataAccessError> {
    let (input, object_value_invalid) = parse_simple_u8_data(input)?;
    Ok((
        input,
        DataAccessError::ObjectValueInvalid {
            object_value_invalid,
        },
    ))
}

pub fn parse_data_access_error(
    input: &[u8],
    _data_access_error_tl_tag: u8,
) -> IResult<&[u8], DataAccessError> {
    let (input, data_access_error) = match _data_access_error_tl_tag.bitand(0x1f) {
        0x0 => parse_data_access_error_object_invalidated(input),
        0x01 => parse_data_access_error_hardware_fault(input),
        0x02 => parse_data_access_error_temporarily_unavailable(input),
        0x03 => parse_data_access_error_object_access_denied(input),
        0x04 => parse_data_access_error_object_undefined(input),
        0x05 => parse_data_access_error_invalid_address(input),
        0x06 => parse_data_access_error_type_unsupported(input),
        0x07 => parse_data_access_error_type_inconsistent(input),
        0x08 => parse_data_access_error_object_attribute_inconsistent(input),
        0x09 => parse_data_access_error_object_access_unsupported(input),
        0x0a => parse_data_access_error_object_non_existent(input),
        0x0b => parse_data_access_error_object_value_invalid(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, data_access_error))
}

fn parse_access_result_access_result_failure(input: &[u8]) -> IResult<&[u8], AccessResult> {
    let (input, _data_access_error_tl) = ber_tl(input)?;
    let (input, data_access_error) = parse_data_access_error(input, _data_access_error_tl.tag)?;
    Ok((
        input,
        AccessResult::AccessResultFailure { data_access_error },
    ))
}

fn parse_access_result_access_result_success(input: &[u8]) -> IResult<&[u8], AccessResult> {
    let (input, data) = parse_simple_item(input)?;
    Ok((input, AccessResult::AccessResultSuccess { data }))
}

pub fn parse_access_result(
    input: &[u8],
    _access_result_tl_tag: u8,
) -> IResult<&[u8], AccessResult> {
    let (input, access_result) = match _access_result_tl_tag.bitand(0x1f) {
        0x0 => parse_access_result_access_result_failure(input),
        0x01 => parse_access_result_access_result_success(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, access_result))
}

pub fn parse_access_result_struct(input: &[u8]) -> IResult<&[u8], AccessResultStruct> {
    let (input, _access_result_tl) = ber_tl(input)?;
    let (input, access_result) = parse_access_result(input, _access_result_tl.tag)?;
    Ok((input, AccessResultStruct { access_result }))
}

pub fn parse_list_of_access_result(input: &[u8]) -> IResult<&[u8], ListOfAccessResult> {
    let (input, _loar_tl) = ber_tl(input)?;
    /* LimitedLenVecLoopField Start */
    let mut loar = Vec::new();
    let mut _loar: AccessResultStruct;
    let mut input = input;
    let len_flag = input.len() - _loar_tl.length as usize;
    while input.len() > len_flag {
        (input, _loar) = parse_access_result_struct(input)?;
        loar.push(_loar);
    }
    let input = input;
    /* LimitedLenVecLoopField End. */
    Ok((input, ListOfAccessResult { loar }))
}

pub fn parse_list_of_identifier(input: &[u8]) -> IResult<&[u8], ListOfIdentifier> {
    let (input, _loar_tl) = ber_tl(input)?;
    /* LimitedLenVecLoopField Start */
    let mut loar = Vec::new();
    let mut _loar: &[u8];
    let mut input = input;
    let len_flag = input.len() - _loar_tl.length as usize;
    while input.len() > len_flag {
        (input, _loar) = take(input.len() as usize)(input)?;
        loar.push(_loar);
    }
    let input = input;
    /* LimitedLenVecLoopField End. */
    Ok((input, ListOfIdentifier { loar }))
}

pub fn parse_init_detail_request(input: &[u8]) -> IResult<&[u8], InitDetailRequest> {
    let (input, proposed_version_number) = parse_simple_item(input)?;
    let (input, proposed_parameter_cbb) = parse_simple_item(input)?;
    let (input, service_supported_calling) = parse_simple_item(input)?;
    Ok((
        input,
        InitDetailRequest {
            proposed_version_number,
            proposed_parameter_cbb,
            service_supported_calling,
        },
    ))
}

pub fn parse_init_detail_response(input: &[u8]) -> IResult<&[u8], InitDetailResponse> {
    let (input, proposed_version_number) = parse_simple_item(input)?;
    let (input, proposed_parameter_cbb) = parse_simple_item(input)?;
    let (input, service_supported_called) = parse_simple_item(input)?;
    Ok((
        input,
        InitDetailResponse {
            proposed_version_number,
            proposed_parameter_cbb,
            service_supported_called,
        },
    ))
}

pub fn parse_invoke_id(input: &[u8]) -> IResult<&[u8], InvokeId> {
    let (input, invoke_id) = u8(input)?;
    Ok((input, InvokeId { invoke_id }))
}

fn parse_variable_access_specification_choice_list_of_variable(
    input: &[u8],
) -> IResult<&[u8], VariableAccessSpecificationChoice> {
    let (input, res) = parse_list_of_variable_specification(input)?;
    Ok((
        input,
        VariableAccessSpecificationChoice::ListOfVariable { res },
    ))
}

fn parse_variable_access_specification_choice_varibale_list_name(
    input: &[u8],
) -> IResult<&[u8], VariableAccessSpecificationChoice> {
    let (input, _object_name_tl) = ber_tl(input)?;
    let (input, object_name) = parse_object_name(input, _object_name_tl.tag)?;
    Ok((
        input,
        VariableAccessSpecificationChoice::VaribaleListName { object_name },
    ))
}

pub fn parse_variable_access_specification_choice(
    input: &[u8],
    _variable_access_specification_choice_tl_tag: u8,
) -> IResult<&[u8], VariableAccessSpecificationChoice> {
    let (input, variable_access_specification_choice) =
        match _variable_access_specification_choice_tl_tag.bitand(0x1f) {
            0x0 => parse_variable_access_specification_choice_list_of_variable(input),
            0x01 => parse_variable_access_specification_choice_varibale_list_name(input),
            _ => Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Verify,
            ))),
        }?;
    Ok((input, variable_access_specification_choice))
}

fn parse_read_request_choice_read_request_choice_default(
    input: &[u8],
) -> IResult<&[u8], ReadRequestChoice> {
    let (input, _variable_access_specification_choice_tl) = ber_tl(input)?;
    let (input, variable_access_specification_choice) = parse_variable_access_specification_choice(
        input,
        _variable_access_specification_choice_tl.tag,
    )?;
    Ok((
        input,
        ReadRequestChoice::ReadRequestChoiceDefault {
            variable_access_specification_choice,
        },
    ))
}

fn parse_read_request_choice_read_request_choice_otherwise(
    input: &[u8],
) -> IResult<&[u8], ReadRequestChoice> {
    let (input, specification_with_result) = u8(input)?;
    let (input, _variable_access_specification_choice_struct_tl) = ber_tl(input)?;
    let (input, _variable_access_specification_choice_tl) = ber_tl(input)?;
    let (input, variable_access_specification_choice) = parse_variable_access_specification_choice(
        input,
        _variable_access_specification_choice_tl.tag,
    )?;
    Ok((
        input,
        ReadRequestChoice::ReadRequestChoiceOtherwise {
            specification_with_result,
            variable_access_specification_choice,
        },
    ))
}

pub fn parse_read_request_choice<'a>(
    input: &'a [u8],
    _read_request_choice_tl: &BerTL,
) -> IResult<&'a [u8], ReadRequestChoice<'a>> {
    let (input, read_request_choice) = match _read_request_choice_tl.tag {
        0x81 => parse_read_request_choice_read_request_choice_default(input),
        0x80 => parse_read_request_choice_read_request_choice_otherwise(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, read_request_choice))
}

fn parse_read_response_choice_read_response_choice_none(
    input: &[u8],
) -> IResult<&[u8], ReadResponseChoice> {
    Ok((input, ReadResponseChoice::ReadResponseChoiceNone {}))
}

fn parse_read_response_choice_read_response_choice_with_data(
    input: &[u8],
) -> IResult<&[u8], ReadResponseChoice> {
    let (input, _list_of_access_result_tl) = ber_tl(input)?;
    let (input, list_of_access_result) = parse_list_of_access_result(input)?;
    Ok((
        input,
        ReadResponseChoice::ReadResponseChoiceWithData {
            list_of_access_result,
        },
    ))
}

pub fn parse_read_response_choice(input: &[u8]) -> IResult<&[u8], ReadResponseChoice> {
    let (input, read_response_choice) = match input.len() {
        0x0 => parse_read_response_choice_read_response_choice_none(input),
        _ => parse_read_response_choice_read_response_choice_with_data(input),
    }?;
    Ok((input, read_response_choice))
}

fn parse_write_response_choice_write_response_choice_failure(
    input: &[u8],
) -> IResult<&[u8], WriteResponseChoice> {
    let (input, _data_access_error_tl) = ber_tl(input)?;
    let (input, data_access_error) = parse_data_access_error(input, _data_access_error_tl.tag)?;
    Ok((
        input,
        WriteResponseChoice::WriteResponseChoiceFailure { data_access_error },
    ))
}

#[inline(always)]
fn parse_write_response_choice_write_response_choice_success(
    input: &[u8],
) -> IResult<&[u8], WriteResponseChoice> {
    Ok((input, WriteResponseChoice::WriteResponseChoiceSuccess {}))
}

pub fn parse_write_response_choice(
    input: &[u8],
    _write_response_choice_tl_tag: u8,
) -> IResult<&[u8], WriteResponseChoice> {
    let (input, write_response_choice) = match _write_response_choice_tl_tag.bitand(0x1f) {
        0x0 => parse_write_response_choice_write_response_choice_failure(input),
        0x01 => parse_write_response_choice_write_response_choice_success(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, write_response_choice))
}

fn parse_confirmed_service_request_choice_get_name_list_request(
    input: &[u8],
) -> IResult<&[u8], ConfirmedServiceRequestChoice> {
    let (input, _object_class_tl) = ber_tl(input)?;
    let (input, object_class) = parse_object_class(input, _object_class_tl.tag)?;
    let (input, _object_scope_tl) = ber_tl(input)?;
    let (input, object_scope) = parse_object_scope(input, _object_scope_tl.tag)?;
    Ok((
        input,
        ConfirmedServiceRequestChoice::GetNameListRequest {
            object_class,
            object_scope,
        },
    ))
}

#[inline(always)]
fn parse_confirmed_service_request_choice_identify_request(
    input: &[u8],
) -> IResult<&[u8], ConfirmedServiceRequestChoice> {
    Ok((input, ConfirmedServiceRequestChoice::IdentifyRequest {}))
}

fn parse_confirmed_service_request_choice_read_request(
    input: &[u8],
) -> IResult<&[u8], ConfirmedServiceRequestChoice> {
    let (input, _read_request_choice_tl) = ber_tl(input)?;
    let (input, read_request_choice) = parse_read_request_choice(input, &_read_request_choice_tl)?;
    Ok((
        input,
        ConfirmedServiceRequestChoice::ReadRequest {
            read_request_choice,
        },
    ))
}

fn parse_confirmed_service_request_choice_write_request(
    input: &[u8],
) -> IResult<&[u8], ConfirmedServiceRequestChoice> {
    let (input, _variable_access_specification_choice_tl) = ber_tl(input)?;
    let (input, variable_access_specification_choice) = parse_variable_access_specification_choice(
        input,
        _variable_access_specification_choice_tl.tag,
    )?;
    let (input, _list_of_data_tl) = ber_tl(input)?;
    let (input, _lod_tl) = ber_tl(input)?;
    /* LimitedLenVecLoopField Start */
    let mut lod = Vec::new();
    let mut _lod: SimpleItem;
    let mut input = input;
    let len_flag = input.len() - _lod_tl.length as usize;
    while input.len() > len_flag {
        (input, _lod) = parse_simple_item(input)?;
        lod.push(_lod);
    }
    let input = input;
    /* LimitedLenVecLoopField End. */
    Ok((
        input,
        ConfirmedServiceRequestChoice::WriteRequest {
            variable_access_specification_choice,
            lod,
        },
    ))
}

fn parse_confirmed_service_request_choice_get_named_variable_list_attributes_request(
    input: &[u8],
) -> IResult<&[u8], ConfirmedServiceRequestChoice> {
    let (input, _object_name_tl) = ber_tl(input)?;
    let (input, object_name) = parse_object_name(input, _object_name_tl.tag)?;
    Ok((
        input,
        ConfirmedServiceRequestChoice::GetNamedVariableListAttributesRequest { object_name },
    ))
}

pub fn parse_confirmed_service_request_choice(
    input: &[u8],
    _service_tl_tag: u8,
) -> IResult<&[u8], ConfirmedServiceRequestChoice> {
    let (input, confirmed_service_request_choice) = match _service_tl_tag.bitand(0x1f) {
        0x0 => parse_confirmed_service_request_choice_get_name_list_request(input),
        0x02 => parse_confirmed_service_request_choice_identify_request(input),
        0x04 => parse_confirmed_service_request_choice_read_request(input),
        0x05 => parse_confirmed_service_request_choice_write_request(input),
        0x0c => {
            parse_confirmed_service_request_choice_get_named_variable_list_attributes_request(input)
        }
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, confirmed_service_request_choice))
}

fn parse_confirmed_service_response_choice_get_name_list_response(
    input: &[u8],
) -> IResult<&[u8], ConfirmedServiceResponseChoice> {
    let (input, _list_of_identifier_tl) = ber_tl(input)?;
    let (input, list_of_identifier) = parse_list_of_identifier(input)?;
    let (input, _more_follows_tl) = ber_tl(input)?;
    let (input, more_follows) = u8(input)?;
    Ok((
        input,
        ConfirmedServiceResponseChoice::GetNameListResponse {
            list_of_identifier,
            more_follows,
        },
    ))
}

fn parse_confirmed_service_response_choice_identify_response(
    input: &[u8],
) -> IResult<&[u8], ConfirmedServiceResponseChoice> {
    let (input, _vendor_name_tl) = ber_tl(input)?;
    let (input, vendor_name) = parse_simple_item(input)?;
    let (input, _model_name_tl) = ber_tl(input)?;
    let (input, model_name) = parse_simple_item(input)?;
    let (input, _revision_tl) = ber_tl(input)?;
    let (input, revision) = parse_simple_item(input)?;
    Ok((
        input,
        ConfirmedServiceResponseChoice::IdentifyResponse {
            vendor_name,
            model_name,
            revision,
        },
    ))
}

fn parse_confirmed_service_response_choice_read_response(
    input: &[u8],
) -> IResult<&[u8], ConfirmedServiceResponseChoice> {
    let (input, _read_response_choice_tl) = ber_tl(input)?;
    let (input, read_response_choice) = parse_read_response_choice(input)?;
    Ok((
        input,
        ConfirmedServiceResponseChoice::ReadResponse {
            read_response_choice,
        },
    ))
}

fn parse_confirmed_service_response_choice_write_response(
    input: &[u8],
) -> IResult<&[u8], ConfirmedServiceResponseChoice> {
    let (input, _write_response_choice_tl) = ber_tl(input)?;
    let (input, write_response_choice) =
        parse_write_response_choice(input, _write_response_choice_tl.tag)?;
    Ok((
        input,
        ConfirmedServiceResponseChoice::WriteResponse {
            write_response_choice,
        },
    ))
}

fn parse_confirmed_service_response_choice_get_named_variable_list_attributes_response(
    input: &[u8],
) -> IResult<&[u8], ConfirmedServiceResponseChoice> {
    let (input, _mms_deleteable_tl) = ber_tl(input)?;
    let (input, mms_deleteable) = u8(input)?;
    let (input, _list_of_variable_specification_tl) = ber_tl(input)?;
    let (input, list_of_variable_specification) = parse_list_of_variable_specification(input)?;
    Ok((
        input,
        ConfirmedServiceResponseChoice::GetNamedVariableListAttributesResponse {
            mms_deleteable,
            list_of_variable_specification,
        },
    ))
}

pub fn parse_confirmed_service_response_choice(
    input: &[u8],
    _service_tl_tag: u8,
) -> IResult<&[u8], ConfirmedServiceResponseChoice> {
    let (input, confirmed_service_response_choice) = match _service_tl_tag.bitand(0x1f) {
        0x0 => parse_confirmed_service_response_choice_get_name_list_response(input),
        0x02 => parse_confirmed_service_response_choice_identify_response(input),
        0x04 => parse_confirmed_service_response_choice_read_response(input),
        0x05 => parse_confirmed_service_response_choice_write_response(input),
        0x0c => {
            parse_confirmed_service_response_choice_get_named_variable_list_attributes_response(
                input,
            )
        }
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, confirmed_service_response_choice))
}

fn parse_confirmed_service_response_struct_confirmed_service_response_struct_none(
    input: &[u8],
) -> IResult<&[u8], ConfirmedServiceResponseStruct> {
    Ok((
        input,
        ConfirmedServiceResponseStruct::ConfirmedServiceResponseStructNone {},
    ))
}

fn parse_confirmed_service_response_struct_confirmed_service_response_struct_with_data(
    input: &[u8],
) -> IResult<&[u8], ConfirmedServiceResponseStruct> {
    let (input, _service_tl) = ber_tl(input)?;
    let (input, service) = parse_confirmed_service_response_choice(input, _service_tl.tag)?;
    Ok((
        input,
        ConfirmedServiceResponseStruct::ConfirmedServiceResponseStructWithData { service },
    ))
}

pub fn parse_confirmed_service_response_struct(
    input: &[u8],
) -> IResult<&[u8], ConfirmedServiceResponseStruct> {
    let (input, confirmed_service_response_struct) = match input.len() {
        0x0 => {
            parse_confirmed_service_response_struct_confirmed_service_response_struct_none(input)
        }
        _ => parse_confirmed_service_response_struct_confirmed_service_response_struct_with_data(
            input,
        ),
    }?;
    Ok((input, confirmed_service_response_struct))
}

fn parse_un_confirmed_choice_information_report(input: &[u8]) -> IResult<&[u8], UnConfirmedChoice> {
    let (input, _variable_access_specification_choice_tl) = ber_tl(input)?;
    let (input, variable_access_specification_choice) = parse_variable_access_specification_choice(
        input,
        _variable_access_specification_choice_tl.tag,
    )?;
    let (input, _list_of_access_result_tl) = ber_tl(input)?;
    let (input, list_of_access_result) = parse_list_of_access_result(input)?;
    Ok((
        input,
        UnConfirmedChoice::InformationReport {
            variable_access_specification_choice,
            list_of_access_result,
        },
    ))
}

pub fn parse_un_confirmed_choice(
    input: &[u8],
    _service_tl_tag: u8,
) -> IResult<&[u8], UnConfirmedChoice> {
    let (input, un_confirmed_choice) = match _service_tl_tag.bitand(0x1f) {
        0x0 => parse_un_confirmed_choice_information_report(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, un_confirmed_choice))
}

fn parse_mms_pdu_choice_confirmed_request(input: &[u8]) -> IResult<&[u8], MmsPduChoice> {
    let (input, _invoke_id_tl) = ber_tl(input)?;
    let (input, invoke_id) = parse_invoke_id(input)?;
    let (input, _service_tl) = ber_tl(input)?;
    let (input, service) = parse_confirmed_service_request_choice(input, _service_tl.tag)?;
    Ok((input, MmsPduChoice::ConfirmedRequest { invoke_id, service }))
}

fn parse_mms_pdu_choice_confirmed_response(input: &[u8]) -> IResult<&[u8], MmsPduChoice> {
    let (input, _invoke_id_tl) = ber_tl(input)?;
    let (input, invoke_id) = parse_invoke_id(input)?;
    let (input, service) = parse_confirmed_service_response_struct(input)?;
    Ok((
        input,
        MmsPduChoice::ConfirmedResponse { invoke_id, service },
    ))
}

fn parse_mms_pdu_choice_un_confirmed(input: &[u8]) -> IResult<&[u8], MmsPduChoice> {
    let (input, _service_tl) = ber_tl(input)?;
    let (input, service) = parse_un_confirmed_choice(input, _service_tl.tag)?;
    Ok((input, MmsPduChoice::UnConfirmed { service }))
}

fn parse_mms_pdu_choice_initiate_request(input: &[u8]) -> IResult<&[u8], MmsPduChoice> {
    let (input, local_detail_calling) = parse_simple_item(input)?;
    let (input, proposed_max_serv_outstanding_calling) = parse_simple_item(input)?;
    let (input, proposed_max_serv_outstanding_called) = parse_simple_item(input)?;
    let (input, proposed_data_structure_nesting_level) = parse_simple_item(input)?;
    let (input, _init_request_detail_tl) = ber_tl(input)?;
    let (input, init_request_detail) = parse_init_detail_request(input)?;
    Ok((
        input,
        MmsPduChoice::InitiateRequest {
            local_detail_calling,
            proposed_max_serv_outstanding_calling,
            proposed_max_serv_outstanding_called,
            proposed_data_structure_nesting_level,
            init_request_detail,
        },
    ))
}

fn parse_mms_pdu_choice_initiate_response(input: &[u8]) -> IResult<&[u8], MmsPduChoice> {
    let (input, local_detail_called) = parse_simple_item(input)?;
    let (input, proposed_max_serv_outstanding_calling) = parse_simple_item(input)?;
    let (input, proposed_max_serv_outstanding_called) = parse_simple_item(input)?;
    let (input, proposed_data_structure_nesting_level) = parse_simple_item(input)?;
    let (input, _init_response_detail_tl) = ber_tl(input)?;
    let (input, init_response_detail) = parse_init_detail_response(input)?;
    Ok((
        input,
        MmsPduChoice::InitiateResponse {
            local_detail_called,
            proposed_max_serv_outstanding_calling,
            proposed_max_serv_outstanding_called,
            proposed_data_structure_nesting_level,
            init_response_detail,
        },
    ))
}

#[inline(always)]
fn parse_mms_pdu_choice_conclude_request(input: &[u8]) -> IResult<&[u8], MmsPduChoice> {
    Ok((input, MmsPduChoice::ConcludeRequest {}))
}

pub fn parse_mms_pdu_choice(
    input: &[u8],
    _mms_pdu_choice_tl_tag: u8,
) -> IResult<&[u8], MmsPduChoice> {
    let (input, mms_pdu_choice) = match _mms_pdu_choice_tl_tag.bitand(0x1f) {
        0x0 => parse_mms_pdu_choice_confirmed_request(input),
        0x01 => parse_mms_pdu_choice_confirmed_response(input),
        0x03 => parse_mms_pdu_choice_un_confirmed(input),
        0x08 => parse_mms_pdu_choice_initiate_request(input),
        0x09 => parse_mms_pdu_choice_initiate_response(input),
        0x0b => parse_mms_pdu_choice_conclude_request(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, mms_pdu_choice))
}

pub fn parse_mms_pdu(input: &[u8]) -> IResult<&[u8], MmsPdu> {
    let (input, _mms_pdu_choice_tl) = ber_tl(input)?;
    let (input, mms_pdu_choice) = parse_mms_pdu_choice(input, _mms_pdu_choice_tl.tag)?;
    Ok((input, MmsPdu { mms_pdu_choice }))
}
