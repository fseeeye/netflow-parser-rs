use std::cmp::Ordering;
use std::ops::BitAnd;

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
use nom::number::complete::{be_u16, be_u32, u8};
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
use crate::packet_level::{L1Packet, L2Packet, L3Packet, L4Packet, L5Packet};
#[allow(unused)]
use crate::packet_quin::{QuinPacket, QuinPacketOptions};
#[allow(unused)]
use crate::LayerType;

use super::parse_l5_eof_layer;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MmsHeader<'a> {
    pub mmsap_header: MmsApHeader,
    pub pdu: MmsPdu<'a>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MmsApHeader {
    pub tpkt: Tpkt,
    pub cotp: Cotp,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Tpkt {
    pub version: u8,
    pub reserved: u8,
    pub length: u16,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CotpPduData {
    ConnectRequest {
        destination_reference: u16,
        source_reference: u16,
        bit_mask: u8,
        parameter_src_tsap: u8,
        parameter_src_length: u8,
        source_tsap: u16,
        parameter_dst_tsap: u8,
        parameter_dst_length: u8,
        destination_tsap: u16,
    },
    ConnectConfirm {
        destination_reference: u16,
        source_reference: u16,
        bit_mask: u8,
        parameter_src_tsap: u8,
        parameter_src_length: u8,
        source_tsap: u16,
        parameter_dst_tsap: u8,
        parameter_dst_length: u8,
        destination_tsap: u16,
        parameter_tpdu_size: u8,
        parameter_tpdu_length: u8,
        tpdu_size: u8,
    },
    Data {
        bit_mask: u8,
    },
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CotpPdu {
    pub pdu_type: u8,
    pub data: CotpPduData,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Cotp{
    pub length: u8,
    pub pdu: CotpPdu,
}


pub fn parse_tpkt(input: &[u8]) -> IResult<&[u8], Tpkt> {
    let (input, version) = u8(input)?;
    let (input, reserved) = u8(input)?;
    let (input, length) = be_u16(input)?;
    Ok((
        input,
        Tpkt {
            version,
            reserved,
            length,
        },
    ))
}

fn parse_connect_request(input: &[u8]) -> IResult<&[u8], CotpPduData> {
    let (input, destination_reference) = be_u16(input)?;
    let (input, source_reference) = be_u16(input)?;
    let (input, bit_mask) = u8(input)?;
    let (input, parameter_src_tsap) = u8(input)?;
    let (input, parameter_src_length) = u8(input)?;
    let (input, source_tsap) = be_u16(input)?;
    let (input, parameter_dst_tsap) = u8(input)?;
    let (input, parameter_dst_length) = u8(input)?;
    let (input, destination_tsap) = be_u16(input)?;
    Ok((
        input,
        CotpPduData::ConnectRequest {
            destination_reference,
            source_reference,
            bit_mask,
            parameter_src_tsap,
            parameter_src_length,
            source_tsap,
            parameter_dst_tsap,
            parameter_dst_length,
            destination_tsap,
        },
    ))
}

fn parse_connect_confirm(input: &[u8]) -> IResult<&[u8], CotpPduData> {
    let (input, destination_reference) = be_u16(input)?;
    let (input, source_reference) = be_u16(input)?;
    let (input, bit_mask) = u8(input)?;
    let (input, parameter_src_tsap) = u8(input)?;
    let (input, parameter_src_length) = u8(input)?;
    let (input, source_tsap) = be_u16(input)?;
    let (input, parameter_dst_tsap) = u8(input)?;
    let (input, parameter_dst_length) = u8(input)?;
    let (input, destination_tsap) = be_u16(input)?;
    let (input, parameter_tpdu_size) = u8(input)?;
    let (input, parameter_tpdu_length) = u8(input)?;
    let (input, tpdu_size) = u8(input)?;
    Ok((
        input,
        CotpPduData::ConnectConfirm {
            destination_reference,
            source_reference,
            bit_mask,
            parameter_src_tsap,
            parameter_src_length,
            source_tsap,
            parameter_dst_tsap,
            parameter_dst_length,
            destination_tsap,
            parameter_tpdu_size,
            parameter_tpdu_length,
            tpdu_size,
        },
    ))
}


pub fn parse_cotp_data_data<'a>(input: &'a[u8]) -> IResult<&[u8], CotpPduData> {
	let (input,bit_mask) = u8(input)?;
    Ok((
        input,
        CotpPduData::Data {
            bit_mask,
        },
    ))
}

pub fn parse_cotp_data(input: &[u8], pdu_type: u8) -> IResult<&[u8], CotpPduData> {
    let (input, data) = match pdu_type {
        0xe0 => parse_connect_request(input),
        0xd0 => parse_connect_confirm(input),
        0xf0 => parse_cotp_data_data(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, data))
}

pub fn parse_cotp_pdu(input: &[u8]) -> IResult<&[u8], CotpPdu> {
    let (input, pdu_type) = u8(input)?;
    let (input, data) = parse_cotp_data(input, pdu_type)?;
    Ok((input, CotpPdu { pdu_type, data }))
}

pub fn parse_cotp(input: &[u8]) -> IResult<&[u8], Cotp> {
    let (input, length) = u8(input)?;
    let (input, pdu) = parse_cotp_pdu(input)?;
    Ok((input, Cotp { length, pdu }))
}

fn ber_indentifier(input: &[u8]) -> IResult<&[u8],u8> {
	let (input,tag) = u8(input)?;
	if tag.bitand(0x1f) > 0x1e{
		panic!("Tag is not Supported!")
	}
	return Ok((input,tag));
}

fn ber_len(input: &[u8]) -> IResult<&[u8],u16> {
	let (mut input, length) = u8(input)?;
	let mut length:u16 = length.into();
	if length.cmp(&0x80) == Ordering::Equal{//不定长 以0x80开头
		loop {
			let item:u16;
			(input,item) = be_u16(input)?;
			if item.cmp(&0x0000) != Ordering::Equal {//以两个0x00结尾
				length = length + item;
			}else {
				break;
			}
		}
		return Ok((input,length));
	}//定长
	else if length<128{//短形式
		Ok((input,length))
	}else {//长形式
		let(input,length) = take((length - 128) as usize)(input)?;
		let length = length[0].into();
		Ok((input,length))
	}
}

fn parse_mmsap_header(input: &[u8]) -> IResult<&[u8], MmsApHeader>{
	let (input, tpkt) = parse_tpkt(input)?;
    let (input, cotp) = parse_cotp(input)?;
	Ok((input,
		MmsApHeader{
			tpkt,
			cotp
		}
	))
}

pub fn parse_mms_header(input: &[u8]) -> IResult<&[u8], MmsHeader> {
	let (input, mmsap_header) = parse_mmsap_header(input)?;
	let (input,pdu) = parse_mms(input)?;
	Ok((input,MmsHeader{mmsap_header,pdu}))
}

pub(crate) fn parse_mms_layer<'a>(
    input: &'a[u8],
    link_layer: LinkLayer,
    network_layer: NetworkLayer<'a>,
    transport_layer: TransportLayer<'a>,
    options: QuinPacketOptions,
) -> QuinPacket<'a> {
    let current_layertype = LayerType::MMS;

    let (input, mms_header) = match parse_mms_header(input) {
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

    if Some(current_layertype) == options.stop {
        let application_layer = ApplicationLayer::MMS(mms_header);
        return QuinPacket::L5(L5Packet {
            link_layer,
            network_layer,
            transport_layer,
            application_layer,
            error: None,
            remain: input,
        });
    };

    let application_layer = ApplicationLayer::MMS(mms_header);
    return parse_l5_eof_layer(
        input,
        link_layer,
        network_layer,
        transport_layer,
        application_layer,
        options,
    );
}

pub fn parse_mms(input: &[u8]) -> IResult<&[u8],MmsPdu>{
	// 7 -- 6 -- 5 -- 4 -- 3 -- 2 -- 1 -- 0		 //
	// 0 -- 0 -- * -- * -- * -- * -- * -- *		 //通用结构体
	// 0 -- 1 -- * -- * -- * -- * -- * -- *		 //应用结构体
	// 1 -- 0 -- * -- * -- * -- * -- * -- *		 //上下文特定结构体
	// 1 -- 1 -- * -- * -- * -- * -- * -- *		 //专用结构体
	// * -- * -- 1 -- * -- * -- * -- * -- *		 //嵌套结构,value为tlv单元
	// * -- * -- 0 -- * -- * -- * -- * -- *		 //基本结构,value为数据单元
	// * -- * -- * -- 1 -- 1 -- 1 -- 1 -- 1		 //后续字节描述tag
	let (input,data) = mms_pdu_choice(input)?;
	Ok((input,MmsPdu{data}))
}

fn mms_pdu_choice(input: &[u8]) -> IResult<&[u8],MmsPduChoice>{
	let (input , tag) = ber_indentifier(input)?;
	let (input, length) = ber_len(input)?;
	match tag.bitand(0x1f) {
		0x00 =>{
			let (input,value) = parse_confirmed_req_pdu(input)?;
			Ok((input,MmsPduChoice::ConfirmedRequest{tag,length,value}))
		},
		0x01 =>{
			let (input,value) = parse_confirmed_rsp_pdu(input)?;
			Ok((input,MmsPduChoice::ConfirmedResponse{tag,length,value}))
		},
		0x03 => {
			let (input,value) = parse_unconfirmed_pdu(input)?;
			Ok((input,MmsPduChoice::UnConfirmed{tag,length,value}))
		},
		0x08 => {
			let (input,value) = parse_initiate_request_pdu(input)?;
			Ok((input,MmsPduChoice::InitiateRequest{tag,length,value}))
		},
		//in this implemented context, _ match to 0x09
		_ => {
			let (input,value) = parse_initiate_response_pdu(input)?;
			Ok((input,MmsPduChoice::InitiateResponse{tag,length,value}))
		}
	}
}

fn parse_confirmed_req_pdu(input: &[u8]) -> IResult<&[u8],ConfirmedRequestPDU> {
	let (input,invoke_id) = be_u32(input)?;
	let (input,service) = parse_confirmed_req_pdu_choice(input)?;
	Ok((input,ConfirmedRequestPDU{invoke_id,service}))
}

fn parse_confirmed_rsp_pdu(input: &[u8]) -> IResult<&[u8],ConfirmedResponsePDU> {
	let (input,invoke_id) = be_u32(input)?;
	let (input,service) = parse_confirmed_rsp_pdu_choice(input)?;
	Ok((input,ConfirmedResponsePDU{invoke_id,service}))
}

fn parse_unconfirmed_pdu(input:&[u8]) -> IResult<&[u8],UnConfirmedPDU> {
	let (input,service) = parse_unconfirmed_pdu_choice(input)?;
	Ok((input,UnConfirmedPDU{service}))
}

fn parse_initiate_request_pdu(input:&[u8]) -> IResult<&[u8],InitiateRequestPDU> {
	let (input,local_detail_calling) = parse_simple_item(input)?;
	let (input,proposed_max_serv_outstanding_calling) = parse_simple_item(input)?;
	let (input,proposed_max_serv_outstanding_called) = parse_simple_item(input)?;
	let (input,proposed_data_structure_nesting_level) = parse_simple_item(input)?;
	let (input,init_request_detail) = parse_init_request_detail(input)?;

	Ok((input,
		InitiateRequestPDU{
			local_detail_calling,
			proposed_max_serv_outstanding_calling,
			proposed_max_serv_outstanding_called,
			proposed_data_structure_nesting_level,
			init_request_detail
		}
	))
}

fn parse_initiate_response_pdu(input:&[u8]) -> IResult<&[u8],InitiateResponsePDU> {
	let (input,local_detail_called) = parse_simple_item(input)?;
	let (input,proposed_max_serv_outstanding_calling) = parse_simple_item(input)?;
	let (input,proposed_max_serv_outstanding_called) = parse_simple_item(input)?;
	let (input,proposed_data_structure_nesting_level) = parse_simple_item(input)?;
	let (input,init_response_detail) = parse_init_response_detail(input)?;

	Ok((input,
		InitiateResponsePDU{
			local_detail_called,
			proposed_max_serv_outstanding_calling,
			proposed_max_serv_outstanding_called,
			proposed_data_structure_nesting_level,
			init_response_detail
		}
	))
}

fn parse_confirmed_req_pdu_choice(input: &[u8]) -> IResult<&[u8],ConfirmedServiceRequestChoice> {
	let (input , tag) = ber_indentifier(input)?;
	let (input, length) = ber_len(input)?;

	match tag.bitand(0x1f) {
		0x01 => {
			let(input,res) = parse_confirmed_get_name_list_request(input)?;
			Ok((input,ConfirmedServiceRequestChoice::GetNameListRequest{tag,length,res}))
		},
		0x02 => {
			//null
			let (input,res) = take(length as usize)(input)?;
			Ok((input,ConfirmedServiceRequestChoice::IdentifyRequest{tag,length,res}))
		},
		0x04 => {
			let(input,res) = parse_confirmed_read_request(input)?;
			Ok((input,ConfirmedServiceRequestChoice::ReadRequest{tag,length,res}))
		},
		0x05 => {
			let (input,res) = parse_confirmed_write_request(input)?;
			Ok((input,ConfirmedServiceRequestChoice::WriteRequest{tag,length,res}))
		},
		//in this implemented context, _ match to 0xc
		_ => {
			let (input,res) = parse_object_name(input)?;
			Ok((input,ConfirmedServiceRequestChoice::GetNamedVariableListRequest{tag,length,res:GetNamedVariableListRequestChoice{object_name:res}}))
		}
	}
}

fn parse_confirmed_rsp_pdu_choice(input: &[u8]) -> IResult<&[u8],ConfirmedServiceResponseChoice> {
	let (input , tag) = ber_indentifier(input)?;
	let (input, length) = ber_len(input)?;

	match tag.bitand(0x1f) {
		0x01 => {
			let(input,res) = parse_confirmed_get_name_list_response(input)?;
			Ok((input,ConfirmedServiceResponseChoice::GetNameListResponse{tag,length,res}))
		},
		0x02 => {
			let(input,res) = parse_identifier_response(input)?;
			Ok((input,ConfirmedServiceResponseChoice::IdentifyResponse{tag,length,res}))
		},
		0x04 => {
			let(input,res) = parse_confirmed_read_write_response(input)?;
			Ok((input,ConfirmedServiceResponseChoice::ReadResponse{tag,length,res}))
		},
		0x05 => {
			let (input,res) = parse_confirmed_read_write_response(input)?;
			Ok((input,ConfirmedServiceResponseChoice::WriteResponse{tag,length,res}))
		},
		//in this implemented context, _ match to 0xc
		_ => {
			let (input,res) = parse_confirmed_get_named_variable_list_response(input)?;
			Ok((input,ConfirmedServiceResponseChoice::GetNamedVariableListResponse{tag,length,res}))
		}
	}
}

fn parse_unconfirmed_pdu_choice(input: &[u8]) -> IResult<&[u8],UnConfirmedChoice> {
	let (input, tag) = ber_indentifier(input)?;
	let (input, length) = ber_len(input)?;

	match tag.bitand(0x1f) {
		//this implement only matches to 0x00
		_ => {
			let (input, ir) = parse_information_report(input)?;
			Ok((input,UnConfirmedChoice::InformationReport{tag,length,ir}))
		},
	}
}

fn parse_init_request_detail(input: &[u8]) -> IResult<&[u8],InitDetailRequest> {
	let (input,proposed_version_number) = parse_simple_item(input)?;
	let (input,proposed_parameter_cbb) = parse_simple_item(input)?;
	let (input,service_supported_calling) = parse_simple_item(input)?;

	Ok((input,InitDetailRequest{proposed_version_number,proposed_parameter_cbb,service_supported_calling}))
}

fn parse_init_response_detail(input: &[u8]) -> IResult<&[u8],InitDetailResponse> {
	let (input,proposed_version_number) = parse_simple_item(input)?;
	let (input,proposed_parameter_cbb) = parse_simple_item(input)?;
	let (input,service_supported_called) = parse_simple_item(input)?;

	Ok((input,InitDetailResponse{proposed_version_number,proposed_parameter_cbb,service_supported_called}))
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Identifier<'a> {
	Item{ tag:u8,length:u16,value:&'a[u8] }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IdentifierResponseChoice<'a> {
	pub vendor_name:SimpleItem<'a>,
	pub model_name:SimpleItem<'a>,
	pub revision:SimpleItem<'a>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ObjectClass<'a> {
	NamedVariable{ tag:u8,length:u16,value:&'a[u8] },
	ScatteredAccess{ tag:u8,length:u16,value:&'a[u8] },
	NamedVariableList{ tag:u8,length:u16,value:&'a[u8] },
	NamedType{ tag:u8,length:u16,value:&'a[u8] },
	Semaphore{ tag:u8,length:u16,value:&'a[u8] },
	EventCondition{ tag:u8,length:u16,value:&'a[u8] },
	EventAction{ tag:u8,length:u16,value:&'a[u8] },
	EventEnrollment{ tag:u8,length:u16,value:&'a[u8] },
	Journal{ tag:u8,length:u16,value:&'a[u8] },
	Domain{ tag:u8,length:u16,value:&'a[u8] },
	ProgramInvocation{ tag:u8,length:u16,value:&'a[u8] },
	OperatorStation{ tag:u8,length:u16,value:&'a[u8] },

}
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ObjectScope<'a> {
	Vmd{ tag:u8,length:u16,value:Identifier<'a> },
	Domain{ tag:u8,length:u16,domain_id:Identifier<'a>, item_id:Identifier<'a> },
	AaSpecific{ tag:u8,length:u16,value:Identifier<'a> },
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ObjectName<'a> {
	Vmd{ tag:u8,length:u16,value:Identifier<'a> },
	Domain{ tag:u8,length:u16,domain_id:Identifier<'a>, item_id:Identifier<'a> },
	AaSpecific{ tag:u8,length:u16,value:Identifier<'a>},
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum VariableSpecification<'a> {
	Name{tag:u8,length:u16,res:ObjectName<'a>},
	Others{ tag:u8,length:u16,value:&'a[u8] },
	// Address,
	// VariableDescription,
	// ScattereAccessDescription,
	// Invalidated
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum VaribaleAccessSpecificationChoice<'a> {//required by ReadRequestChoice
	ListOfVariable{tag:u8,length:u16,res:ListOfVariableSpecification<'a>},
	VaribaleListName{tag:u8,length:u16,res:ObjectName<'a>}
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SimpleItem<'a>{
	pub tag:u8,
	pub length:u16,
	pub data:&'a[u8],
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Data<'a>{
	pub data:SimpleItem<'a>
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DataAccessError{
	Objectnvalidated{ tag:u8,length:u16,value:u8},
	Hardwarefault{ tag:u8,length:u16,value:u8},
	TemporarilyUnavailable{ tag:u8,length:u16,value:u8},
	ObjectAccessDenied{ tag:u8,length:u16,value:u8},
	ObjectUndefined{ tag:u8,length:u16,value:u8},
	InvalidAddress{ tag:u8,length:u16,value:u8},
	TypeUnsupported{ tag:u8,length:u16,value:u8},
	TypeInconsistent{ tag:u8,length:u16,value:u8},
	ObjectAttributeInconsistent{ tag:u8,length:u16,value:u8},
	ObjectAccessUnsupported{ tag:u8,length:u16,value:u8},
	ObjectNonExistent{ tag:u8,length:u16,value:u8},
	ObjectValuenvalid{ tag:u8,length:u16,value:u8},
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AccessResult<'a>{
	Failure{tag:u8,length:u16,failure:DataAccessError},
	Success{tag:u8,length:u16,success:Data<'a>}
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BoolResult{
	pub tag:u8,
	pub length:u16,
	pub result:bool,
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ListOfAccessResult<'a>{
	pub tag:u8,
	pub length:u16,
	pub loar:Vec<AccessResult<'a>>
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ListOfData<'a>{//required by ConfirmedServiceRequestChoice
	pub tag:u8,
	pub length:u16,
	pub data:Vec<SimpleItem<'a>>
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ListOfVariableSpecification<'a>{
	pub tag:u8,
	pub length:u16,
	pub data:Vec<VariableSpecification<'a>>
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct GetNamedVariableListRequestChoice<'a>{//required by ConfirmedServiceRequestChoice
	pub object_name:ObjectName<'a>
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct GetNamedVariableListResponseChoice<'a>{
	pub mms_deleteable:BoolResult,
	pub lov:ListOfVariableSpecification<'a>
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct WriteRequestChoice<'a>{//required by ConfirmedServiceRequestChoice
	pub vas:VaribaleAccessSpecificationChoice<'a>,
	pub lod:ListOfData<'a>
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ReadRequestChoice<'a>{//required by ConfirmedServiceRequestChoice
	Default{tag:u8,length:u16,res:VaribaleAccessSpecificationChoice<'a>},
	Otherwise{specification_with_result:BoolResult,tag:u8,length:u16,res:VaribaleAccessSpecificationChoice<'a>}
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ReadWriteResponseChoice<'a>{//required by ConfirmedServiceResponseChoice
	Default{tag:u8,length:u16,loar:ListOfAccessResult<'a>},
	Otherwise{vas:VaribaleAccessSpecificationChoice<'a>,tag:u8,length:u16,loar:ListOfAccessResult<'a>}
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct GetNameListRequestChoice<'a>{//required by ConfirmedServiceRequestChoice
	pub object_class:ObjectClass<'a>,
	pub object_scope:ObjectScope<'a>,
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct GetNameListResponseChoice<'a>{//required by ConfirmedServiceResponseChoice
	pub list_of_identifier:Identifier<'a>,
	pub more_follows:BoolResult,
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct InformationReportChoice<'a>{
	pub vas:VaribaleAccessSpecificationChoice<'a>,
	pub loar:ListOfAccessResult<'a>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum UnConfirmedChoice<'a> {//required by ConfirmedRequestPDU
	InformationReport{tag:u8,length:u16,ir:InformationReportChoice<'a>},				//		0
	UnsolicitedStatus,				//		1
	EventNotification,				//		2
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ConfirmedServiceResponseChoice<'a> {//required by ConfirmedRequestPDU
	GetNameListResponse{tag:u8,length:u16,res:GetNameListResponseChoice<'a>},						//		1
	IdentifyResponse{tag:u8,length:u16,res:IdentifierResponseChoice<'a>},							//		2
	ReadResponse{tag:u8,length:u16,res:ReadWriteResponseChoice<'a>},								//		4
	WriteResponse{tag:u8,length:u16,res:ReadWriteResponseChoice<'a>},								//		5
	GetNamedVariableListResponse{tag:u8,length:u16,res:GetNamedVariableListResponseChoice<'a>},				//		12
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ConfirmedServiceRequestChoice<'a> {//required by ConfirmedRequestPDU
	// increase from 0;
	// StatusRequest,
	GetNameListRequest{tag:u8,length:u16,res:GetNameListRequestChoice<'a>},		//		1
	IdentifyRequest{ tag:u8,length:u16,res:&'a[u8] },							//		2
	// RenameRequest,
	ReadRequest{tag:u8,length:u16,res:ReadRequestChoice<'a>},					//		4
	WriteRequest{tag:u8,length:u16,res:WriteRequestChoice<'a>},					//		5
	// GetVariableAccessAttributesRequest,
	// DefineNamedVariableRequest,
	// DefineScatteredAccess,
	// GetScatteredAccessAttributes,
	// DeleteVariableAccess,
	// DefineNamedVariableListRequest,
	GetNamedVariableListRequest{tag:u8,length:u16,res:GetNamedVariableListRequestChoice<'a>},			//		12
	// DeleteNamedVariableListRequest,
	// DefineNamedType,
	// GetNamedTypeAttributes,
	// DeleteNamedType,
	// InputRequest,
	// OutputRequest,
	// TakeControlRequest,
	// RelinquishControlRequest,
	// DefineSemaphoreRequest,
	// DeleteSemaphoreRequest,
	// ReportSemaphoreStatusRequest,
	// ReportPoolSemaphoreStatusRequest,
	// ReportSemaphoreEntryStatusRequest,
	// InitiateDownloadSequenceRequest,
	// DownloadSegmentRequest,
	// TerminateDownloadSequenceRequest,
	// InitiateUploadSequenceRequest,
	// UploadSegmentRequest,
	// TerminateUploadSegmentRequest,
	// RequestDomainDownloadRequest,
	// RequestDomainUploadRequest,
	// LoadDomainContentRequest,
	// StoreDomainContentRequest,
	// DeleteDomainRequest,
	// GetDomainAttributesRequest,
	// CreateProgramInvocationRequest,
	// DeleteProgramInvocationRequest,
	// StartRequest,
	// StopRequest,
	// ResumeRequest,
	// ResetRequest,
	// GetProgramInvocationAttributesRequest,
	// ObtainFileRequest,
	// DefineEventConditionRequest,
	// DelteteEventConditionRequest,
	// GetEventConditionAttributesRequest,
	// ReportEventConditionStatusRequest,
	// AlterEventConditionMonitoringRequest,
	// TriggerEventRequest,
	// DefineEventActionRequest,
	// DeleteEventAction,
	// GetEventActionAttributesRequest,
	// ReportEventActionsStatusRequest,
	// DefineEventEnrollmentRequest,
	// DeleteEventEnrollmentRequeset,
	// AlterEventEnrollmentRequest,
	// ReportEventEnrollmentStatusRequest,
	// GetEventEnrollmentStatusRequest,
	// AcknowledgeEventNotificationRequest,
	// GetAlarmSummaryRequest,
	// GetAlarmEnrollmentSummaryRequest,
	// ReadJournalRequeset,
	// WriteJournalRequest,
	// InitializeJournalRequest,
	// ReportJournalRequest,
	// CreateJournalRequest,
	// DeleteJournalRequest,
	// GetCapabilityListRequest,
	// FileOpenRequest,
	// FileReadRequest,
	// FileCloseRequest,
	// FileRenameRequest,
	// FileDeleteRequest,
	// FileDirectoryRequest,
	// AdditionalServiceRequest(AdditionalServiceRequestChoice),
	// ChoiceIsReserved,
	// GetDateExchangeAttributesRequest,
	// ExchangeDataRequest,
	// DefineAccexxControlListRequest,
	// GetAccessControlListAttributesRequest,
	// ReportAccessControlledObject,
	// DeleteAccessControlListRequest,
	// ChangeAccessControlListRequest,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct InitDetailRequest<'a>{
	pub proposed_version_number : SimpleItem<'a>,
	pub proposed_parameter_cbb : SimpleItem<'a>,
	pub service_supported_calling : SimpleItem<'a>,
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct InitDetailResponse<'a>{
	pub proposed_version_number : SimpleItem<'a>,
	pub proposed_parameter_cbb : SimpleItem<'a>,
	pub service_supported_called : SimpleItem<'a>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct  ConfirmedRequestPDU<'a> {//required by MmsPduChoice
	pub invoke_id:u32,
	pub service:ConfirmedServiceRequestChoice<'a>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct  ConfirmedResponsePDU<'a> {//required by MmsPduChoice
	pub invoke_id:u32,
	pub service:ConfirmedServiceResponseChoice<'a>,
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct  UnConfirmedPDU<'a> {//required by MmsPduChoice
	pub service:UnConfirmedChoice<'a>,
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct InitiateRequestPDU<'a>{
	pub local_detail_calling : SimpleItem<'a>,
	pub proposed_max_serv_outstanding_calling : SimpleItem<'a>,
	pub proposed_max_serv_outstanding_called : SimpleItem<'a>,
	pub proposed_data_structure_nesting_level : SimpleItem<'a>,
	pub init_request_detail:InitDetailRequest<'a>
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct InitiateResponsePDU<'a>{
	pub local_detail_called : SimpleItem<'a>,
	pub proposed_max_serv_outstanding_calling : SimpleItem<'a>,
	pub proposed_max_serv_outstanding_called : SimpleItem<'a>,
	pub proposed_data_structure_nesting_level : SimpleItem<'a>,
	pub init_response_detail:InitDetailResponse<'a>
}


#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MmsPduChoice<'a>{
	ConfirmedRequest{tag:u8,length:u16,value:ConfirmedRequestPDU<'a>},
	ConfirmedResponse{tag:u8,length:u16,value:ConfirmedResponsePDU<'a>},
	UnConfirmed{tag:u8,length:u16,value:UnConfirmedPDU<'a>},
	InitiateRequest{tag:u8,length:u16,value:InitiateRequestPDU<'a>},
	InitiateResponse{tag:u8,length:u16,value:InitiateResponsePDU<'a>},
}
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MmsPdu<'a>{
	pub data:MmsPduChoice<'a>
}

fn parse_information_report(input:&[u8]) -> IResult<&[u8],InformationReportChoice> {
	let (input, vas) = parse_variable_access_specification(input)?;
	let (input, loar) = parse_list_of_access_result(input)?;

	Ok((input,InformationReportChoice{vas,loar}))
}

fn parse_confirmed_get_named_variable_list_response(input: &[u8]) -> IResult<&[u8],GetNamedVariableListResponseChoice> {
	let (input, tag) = ber_indentifier(input)?;
	let (input, length) = ber_len(input)?;
	let (input, result) = u8(input)?;
	let mut mms_deleteable:BoolResult;
	if let 0x00 = result {
		mms_deleteable = BoolResult{tag,length,result:false};
	}else{
		mms_deleteable = BoolResult{tag,length,result:true};
	}

	let (input, tag) = ber_indentifier(input)?;
	let (input, length) = ber_len(input)?;
	let (input,mut _input) = take(length as usize)(input)?;
	let mut vlov = Vec::new();
	loop {
		if _input.len()<=0{
			break;
		}
		let item:VariableSpecification;
		(_input,item) = parse_variable_specification(input)?;
		vlov.insert(vlov.len(), item)
	}
	Ok((input,
		GetNamedVariableListResponseChoice{
			mms_deleteable,
			lov:ListOfVariableSpecification{
				tag,length,data:vlov
			}
		}
	))
}

fn parse_simple_item(input: &[u8]) -> IResult<&[u8],SimpleItem> {
	let (input,tag) = ber_indentifier(input)?;
	let (input, length) = ber_len(input)?;
	let (input, data) = take(length as usize)(input)?;
	Ok((input,SimpleItem{tag,length,data}))
}

fn parse_identifier_response(input: &[u8]) -> IResult<&[u8],IdentifierResponseChoice> {
	let (input, vendor_name) = parse_simple_item(input)?;
	let (input, model_name) = parse_simple_item(input)?;
	let (input, revision) = parse_simple_item(input)?;

	Ok((input,IdentifierResponseChoice{vendor_name,model_name,revision}))
}

fn parse_object_name(input: &[u8]) -> IResult<&[u8],ObjectName> {
	let (input,tag) = ber_indentifier(input)?;
	let (input, length) = ber_len(input)?;
	match tag.bitand(0x1f) {
		0x00 => {
			let (input, value) = parse_identifier(input)?;
			Ok((input,ObjectName::Vmd{tag,length,value}))
		},
		0x01 => {
			let (input, domain_id) = parse_identifier(input)?;
			let (input, item_id) = parse_identifier(input)?;
			Ok((input,ObjectName::Domain{tag,length,domain_id,item_id}))
		},
		//in this implemented context, _ match to 0x02
		_ => {
			let (input, value) = parse_identifier(input)?;
			Ok((input,ObjectName::AaSpecific{tag,length,value}))
		},
	}
}

fn parse_object_scope(input: &[u8]) -> IResult<&[u8],ObjectScope> {
		let (input,tag) = ber_indentifier(input)?;
	let (input, length) = ber_len(input)?;
	match tag.bitand(0x1f) {
		0x00 => {
			let (input, value) = parse_identifier(input)?;
			Ok((input,ObjectScope::Vmd{tag,length,value}))
		},
		0x01 => {
			let (input, domain_id) = parse_identifier(input)?;
			let (input, item_id) = parse_identifier(input)?;
			Ok((input,ObjectScope::Domain{tag,length,domain_id,item_id}))
		},
		//in this implemented context, _ match to 0x02
		_ => {
			let (input, value) = parse_identifier(input)?;
			Ok((input,ObjectScope::AaSpecific{tag,length,value}))
		},
	}
}

fn parse_object_class(input: &[u8]) -> IResult<&[u8],ObjectClass> {
	let (input , tag) = ber_indentifier(input)?;
	let (input, length) = ber_len(input)?;
	let (input, value) = take(length as usize)(input)?;
	match tag.bitand(0x1f) {
		0x00 => {
			Ok((input,ObjectClass::NamedVariable{tag,length,value}))
		},
		0x01 => {
			Ok((input,ObjectClass::ScatteredAccess{tag,length,value}))
		},
		0x02 => {
			Ok((input,ObjectClass::NamedVariableList{tag,length,value}))
		},
		0x03 => {
			Ok((input,ObjectClass::NamedType{tag,length,value}))
		},
		0x04 => {
			Ok((input,ObjectClass::Semaphore{tag,length,value}))
		},
		0x05 => {
			Ok((input,ObjectClass::EventCondition{tag,length,value}))
		},
		0x06 => {
			Ok((input,ObjectClass::EventAction{tag,length,value}))
		},
		0x07 => {
			Ok((input,ObjectClass::EventEnrollment{tag,length,value}))
		},
		0x08 => {
			Ok((input,ObjectClass::Journal{tag,length,value}))
		},
		0x09 => {
			Ok((input,ObjectClass::Domain{tag,length,value}))
		},
		0x0a => {
			Ok((input,ObjectClass::ProgramInvocation{tag,length,value}))
		},
		//in this implemented context, _ match to 0x0b
		_ => {
			Ok((input,ObjectClass::OperatorStation{tag,length,value}))
		},
	}
}

fn parse_confirmed_get_name_list_request(input: &[u8]) -> IResult<&[u8],GetNameListRequestChoice> {
	let (input , object_class) = parse_object_class(input)?;
	let (input , object_scope) = parse_object_scope(input)?;

	Ok((input,GetNameListRequestChoice{
		object_class,
		object_scope,
	}))
}

fn parse_confirmed_get_name_list_response(input: &[u8]) -> IResult<&[u8],GetNameListResponseChoice> {
	let (input , list_of_identifier) = parse_identifier(input)?;
	let (input , more_follows) = {
		let (input , tag) = ber_indentifier(input)?;
		let (input, length) = ber_len(input)?;
		let (input,value) = u8(input)?;
		let mut result = false;
		if value != 0{
			result = true;
		}
		Ok((input,BoolResult{tag,length,result}))
	}?;

	Ok((input,GetNameListResponseChoice{
		list_of_identifier,
		more_follows
	}))
}

fn parse_identifier(input: &[u8]) -> IResult<&[u8],Identifier> {
	let (input , tag) = ber_indentifier(input)?;
	let (input, length) = ber_len(input)?;
	let (input, value) = take(length as usize)(input)?;
	Ok((input,Identifier::Item{tag,length,value}))
}

fn parse_confirmed_read_request(input: &[u8]) -> IResult<&[u8],ReadRequestChoice> {
	let (input , tag) = ber_indentifier(input)?;
	let (input, length) = ber_len(input)?;
	let mut result = false;
	if tag == 0x80{
		let (input,value) = u8(input)?;
		if value != 0{
			result = true;
		}
		let (input , _tag) = ber_indentifier(input)?;
		let (input, _length) = ber_len(input)?;
		let (input,res) = parse_variable_access_specification(input)?;
		Ok((input,
			ReadRequestChoice::Otherwise{
				specification_with_result:BoolResult{
					tag,length,result
				},
				tag:_tag,length:_length,res
			}
		))
	}else {
		let (input,res) = parse_variable_access_specification(input)?;
		Ok((input,
			ReadRequestChoice::Default{
				tag,length,res
			}
		))
	}
}

fn parse_data_access_error(input: &[u8]) -> IResult<&[u8],DataAccessError> {
	let (input , tag) = ber_indentifier(input)?;
	let (input, length) = ber_len(input)?;
	let (input, value) = u8(input)?;
	match value.bitand(0x0f) {
		0x00 => {
			Ok((input,DataAccessError::Objectnvalidated{tag,length,value}))
		},
		0x01 => {
			Ok((input,DataAccessError::Hardwarefault{tag,length,value}))
		},
		0x02 => {
			Ok((input,DataAccessError::TemporarilyUnavailable{tag,length,value}))
		},
		0x03 => {
			Ok((input,DataAccessError::ObjectAccessDenied{tag,length,value}))
		},
		0x04 => {
			Ok((input,DataAccessError::ObjectUndefined{tag,length,value}))
		},
		0x05 => {
			Ok((input,DataAccessError::InvalidAddress{tag,length,value}))
		},
		0x06 => {
			Ok((input,DataAccessError::TypeUnsupported{tag,length,value}))
		},
		0x07 => {
			Ok((input,DataAccessError::TypeInconsistent{tag,length,value}))
		},
		0x08 => {
			Ok((input,DataAccessError::ObjectAttributeInconsistent{tag,length,value}))
		},
		0x09 => {
			Ok((input,DataAccessError::ObjectAccessUnsupported{tag,length,value}))
		},
		0x0a => {
			Ok((input,DataAccessError::ObjectNonExistent{tag,length,value}))
		},
		//only match to 0x0b
		_ => {
			Ok((input,DataAccessError::ObjectValuenvalid{tag,length,value}))
		},
	}
}

fn parse_data_access_success(input: &[u8]) -> IResult<&[u8],Data> {
	let(input,data) = parse_simple_item(input)?;
	Ok((input,Data{data}))
}

fn parse_access_result(input: &[u8]) -> IResult<&[u8],AccessResult> {
	let (input , tag) = ber_indentifier(input)?;
	let (input, length) = ber_len(input)?;
	match tag.bitand(0x1f) {
		0x00 => {//failure
			let(input,failure) = parse_data_access_error(input)?;
			Ok((input,AccessResult::Failure{tag,length,failure}))
		},
		//_ only can be failure or success
		_ => {
			let (input,success) = parse_data_access_success(input)?;
			Ok((input,AccessResult::Success{tag,length,success}))
		}
	}
}

fn parse_list_of_access_result(input: &[u8]) -> IResult<&[u8],ListOfAccessResult> {
	let (input , tag) = ber_indentifier(input)?;
	let (input, length) = ber_len(input)?;
	let (input,mut _input) = take(length as usize)(input)?;
	let mut loar = Vec::new();
	loop {
		if _input.len()<=0{
			break;
		}
		let item :AccessResult;
		(_input,item)=parse_access_result(input)?;
		loar.insert(loar.len(), item)
	}
	Ok((input,ListOfAccessResult{tag,length,loar}))
}

fn parse_confirmed_read_write_response(input: &[u8]) -> IResult<&[u8],ReadWriteResponseChoice> {
	let (input , tag) = ber_indentifier(input)?;
	let (input, length) = ber_len(input)?;
	if tag == 0x80{
		let (input,vas) = parse_variable_access_specification(input)?;
		let (input,loar) = parse_list_of_access_result(input)?;
		Ok(( input, ReadWriteResponseChoice::Otherwise{tag,length,vas,loar} ))
	}else {
		let (input,loar) = parse_list_of_access_result(input)?;
		Ok(( input, ReadWriteResponseChoice::Default{ tag,length,loar } ))
	}
}

fn parse_list_of_variable(input: &[u8]) -> IResult<&[u8],ListOfVariableSpecification>{
	let (input , tag) = ber_indentifier(input)?;
	let (input, length) = ber_len(input)?;
	let (input, mut _input) = take(length as usize)(input)?;
	let mut data = Vec::new();
	loop{
		if _input.len()<=0{
			break;
		}
		let item :VariableSpecification;
		(_input,item) = parse_variable_specification(input)?;
		data.insert(data.len(), item)
	}
	Ok((input,ListOfVariableSpecification{tag,length,data}))
}

fn parse_variable_specification(input: &[u8]) -> IResult<&[u8],VariableSpecification> {
	let (input,tag) = ber_indentifier(input)?;
	let (input, length) = ber_len(input)?;
	match tag.bitand(0x1f) {
		0x00 => {
			let (input,res) = parse_object_name(input)?;
			Ok((input,VariableSpecification::Name{tag,length,res}))
		},
		_ => {
			let (input, value) = take(length as usize)(input)?;
			Ok((input,VariableSpecification::Others{tag,length,value}))
		}
	}

}

fn parse_variable_access_specification(input: &[u8]) -> IResult<&[u8],VaribaleAccessSpecificationChoice> {
	let (input , tag) = ber_indentifier(input)?;
	let (input, length) = ber_len(input)?;

	match tag.bitand(0x1f) {
		0x00 => {
			let (input,res) = parse_list_of_variable(input)?;
			Ok((input,VaribaleAccessSpecificationChoice::ListOfVariable{tag,length,res}))
		},
		//only matches to 0x01
		_ => {
			let(input,res) = parse_object_name(input)?;
			Ok((input,VaribaleAccessSpecificationChoice::VaribaleListName{tag,length,res}))
		}
	}
}

fn parse_list_of_data(input: &[u8]) -> IResult<&[u8],ListOfData> {
	let (input , tag) = ber_indentifier(input)?;
	let (input, length) = ber_len(input)?;
	let (input, mut _input) = take(length as usize)(input)?;
	let mut data = Vec::new();
	loop{
		if _input.len()<=0{
			break;
		}
		let item :SimpleItem;
		(_input,item) = parse_simple_item(input)?;
		data.insert(data.len(), item)
	}
	Ok((input,ListOfData{tag,length,data}))
}

fn parse_confirmed_write_request(input: &[u8]) -> IResult<&[u8],WriteRequestChoice> {
	let(input,vas) = parse_variable_access_specification(input)?;
	let(input,lod) = parse_list_of_data(input)?;

	Ok((input,WriteRequestChoice{
		vas,
		lod
	}))
}