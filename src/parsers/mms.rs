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
pub struct MMSHeader<'a> {
    pub tpkt: Tpkt,
    pub cotp: Cotp<'a>,
}

pub fn parse_mms_header<'a>(input: &'a[u8]) -> IResult<&'a[u8], MMSHeader> {
    let (input, tpkt) = parse_tpkt(input)?;
    let (input, cotp) = parse_cotp(input)?;
    Ok((input, MMSHeader { tpkt, cotp }))
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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Tpkt {
    pub version: u8,
    pub reserved: u8,
    pub length: u16,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Data<'a> {
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
		tlv_datas:Vec<TlvItem<'a>>,
    },
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PDU<'a> {
    pub pdu_type: u8,
    pub data: Data<'a>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Cotp<'a> {
    pub length: u8,
    pub pdu: PDU<'a>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TlvValue<'a> {
    Primitive(Box<&'a[u8]>),
	Constructed(Box<TlvItem<'a>>),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TlvItem<'a> {
    pub tag: &'a [u8],
	pub length: u16,
    pub value: TlvValue<'a>,
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

fn parse_connect_request(input: &[u8]) -> IResult<&[u8], Data> {
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
        Data::ConnectRequest {
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

fn parse_connect_confirm(input: &[u8]) -> IResult<&[u8], Data> {
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
        Data::ConnectConfirm {
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

fn get_tlv_length(input: &[u8]) -> IResult<&[u8], u16>{
	let (mut input, length) = u8(input)?;
	let mut length:u16 = length.into();
	if length.cmp(&0x80) == Ordering::Equal{//不定长
		loop {
			let item:u16;
			(input,item) = be_u16(input)?;
			if item.cmp(&0x0000) != Ordering::Equal {
				length += item;
			}else {
				break;
			}
		}
		return Ok((input,length));
	}//定长
	else if length<128{
		Ok((input,length.into()))
	}else {
		let(input,length) = take((length - 128) as usize)(input)?;
		let length = length[0].into();
		Ok((input,length))
	}
}

fn get_tlv_tag(input: &[u8]) -> IResult<&[u8], &[u8]>{
	let (input_tmp,tag_tmp) = take(1 as usize)(input)?;
	if tag_tmp[0].bitand(0x1f) == 0x1f{//多字节表示tag
		let mut nums:usize = 0;
		{//检查tag占几个字节
			let (mut input,mut tag) = u8(input_tmp)?;
			loop {
				if tag<128{
					break;
				}else {
					(input,tag) = u8(input)?;
					nums += 1
				}
			}
		}
		let (input,tag) = take(nums)(input)?;
		//println!("多字节：tag*******--{:#?}--***********",tag);
		return Ok((input,tag));
	}else{//单字节表示tag
		//println!("单字节：tag*******--{:#?}--***********",tag_tmp);
		return Ok((input_tmp,tag_tmp));
	}
}

fn tlv<'a>(input: &'a[u8]) -> IResult<&[u8], TlvItem<'a>>{
	let (input,tag) = get_tlv_tag(input)?;
	let (input,length) = get_tlv_length(input)?;
	if tag[0].bitand(0x20) == 0x20{//value为嵌套类型
		//println!("*******--value:嵌套类型--***********");
		let (input,res) = tlv(input)?;
		return Ok((input,TlvItem{tag,length,value:TlvValue::Constructed(Box::new(res))}));
	}else{//基本类型
		//println!("*******--value:基本类型--***********");
		let (input,value) = take(length as usize)(input)?;
		return Ok((input,TlvItem{tag,length,value:TlvValue::Primitive(Box::new(value))}));
	}
}

fn parse_dt_data<'a>(input: &'a[u8]) -> IResult<&[u8], Data> {
    let (mut input, bit_mask) = u8(input)?;
	let mut tlv_datas = Vec::new();
	loop {
		if input.len()<=0{
			break;
		}
		let item:TlvItem<'a>;
		(input,item) = tlv(input)?;
		tlv_datas.push(item);
	}
    Ok((
        input,
        Data::Data {
            bit_mask,
			tlv_datas
        },
    ))
}


pub fn parse_data(input: &[u8], pdu_type: u8) -> IResult<&[u8], Data> {
    let (input, data) = match pdu_type {
        0xe0 => parse_connect_request(input),
        0xd0 => parse_connect_confirm(input),
        0xf0 => parse_dt_data(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        ))),
    }?;
    Ok((input, data))
}

pub fn parse_pdu(input: &[u8]) -> IResult<&[u8], PDU> {
    let (input, pdu_type) = u8(input)?;
    let (input, data) = parse_data(input, pdu_type)?;
    Ok((input, PDU { pdu_type, data }))
}

pub fn parse_cotp(input: &[u8]) -> IResult<&[u8], Cotp> {
    let (input, length) = u8(input)?;
    let (input, pdu) = parse_pdu(input)?;
    Ok((input, Cotp { length, pdu }))
}
