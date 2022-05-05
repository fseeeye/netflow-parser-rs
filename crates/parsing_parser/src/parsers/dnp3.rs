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
use nom::number::complete::{be_u16, be_u24, be_u32, le_u16, le_u24, le_u32, u8};
#[allow(unused)]
use nom::sequence::tuple;
#[allow(unused)]
use nom::IResult;
use tracing::error;

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
use std::ops::BitAnd;
#[allow(unused)]
use std::ops::BitOr;
#[allow(unused)]
use std::ops::BitXor;

use super::parse_l5_eof_layer;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Dnp3Header {
    pub data_link_layer: DataLinkLayer,
    pub transport_control: TransportControl,
    pub application_layer: Dnp3ApplicationLayer,
}

pub fn parse_dnp3_header(input: &[u8]) -> IResult<&[u8], Dnp3Header> {
    let (input, data_link_layer) = parse_data_link_layer(input)?;
    let (input, transport_control) = parse_transport_control(input)?;
    let (input, application_layer) = parse_dnp3_application_layer(input, data_link_layer.length)?;
    Ok((
        input,
        Dnp3Header {
            data_link_layer,
            transport_control,
            application_layer,
        },
    ))
}

pub fn parse_dnp3_layer<'a>(
    input: &'a [u8],
    link_layer: LinkLayer,
    network_layer: NetworkLayer<'a>,
    transport_layer: TransportLayer<'a>,
    options: &QuinPacketOptions,
) -> QuinPacket<'a> {
    let current_prototype = ProtocolType::Application(ApplicationProtocol::Dnp3);

    let (input, dnp3_header) = match parse_dnp3_header(input) {
        Ok(o) => o,
        Err(e) => {
            error!(
                target: "PARSER(dnp3::parse_dnp3_layer)",
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
        let application_layer = ApplicationLayer::Dnp3(dnp3_header);
        return QuinPacket::L5(L5Packet {
            link_layer,
            network_layer,
            transport_layer,
            application_layer,
            error: None,
            remain: input,
        });
    };

    let application_layer = ApplicationLayer::Dnp3(dnp3_header);
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
pub struct DataLinkLayer {
    pub length: u8,
    pub dl_direction: u8,
    pub dl_primary: u8,
    pub dl_frame_count_bit: u8,
    pub dl_frame_count_valid: u8,
    pub dl_function: u8,
    pub destination: u16,
    pub source: u16,
    pub data_header_crc: u16,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TransportControl {
    pub tr_final: u8,
    pub tr_first: u8,
    pub tr_sequence: u8,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Dnp3ApplicationLayer {
    pub app_control: u8,
    pub function_code: u8,
    pub app_data: Dnp3ApplicationData,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Qualifier {
    prefix_code: u8,
    range_code: u8,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum NumOfItem {
    Qualifier(u32),
    StartStop { start: u32, stop: u32 },
    None,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DataObject {
    pub obj: u16,
    pub qualifier: Qualifier,
    pub num_of_item: NumOfItem,
    // TODO: Points
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Dnp3ApplicationData {
    // 0x00
    Confirm,
    // 0x01
    Read {
        objects: Vec<DataObject>,
    },
    // 0x02
    Write {
        objects: Vec<DataObject>,
    },
    // 0x03
    Select {
        objects: Vec<DataObject>,
    },
    // 0x0d
    ColdRestart,
    // 0x0e
    WarmRestart,
    // 0x12
    StopApplication,
    // 0x14
    EnableSpontaneousMessage {
        objects: Vec<DataObject>,
    },
    // 0x15
    DisableSpontaneousMessage {
        objects: Vec<DataObject>,
    },
    // 0x19
    OpenFile {
        objects: Vec<DataObject>,
    },
    // 0x81
    Response {
        internal_indications: u16,
        objects: Vec<DataObject>,
    },
    // 0x82
    UnsolicitedResponse {
        internal_indications: u16,
        objects: Vec<DataObject>,
    },
}

pub fn parse_data_link_layer(input: &[u8]) -> IResult<&[u8], DataLinkLayer> {
    let (input, data_header_buffer) = peek(take(8usize))(input)?;
    let (input, _) = tag::<_, _, nom::error::Error<&[u8]>>([0x05, 0x64])(input)?;
    let (input, length) = u8(input)?;
    let (input, (dl_direction, dl_primary, dl_frame_count_bit, dl_frame_count_valid, dl_function)) =
        bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
            take_bits(1usize),
            take_bits(1usize),
            take_bits(1usize),
            take_bits(1usize),
            take_bits(4usize),
        )))(input)?;
    let (input, destination) = le_u16(input)?;
    let (input, source) = le_u16(input)?;
    let (input, data_header_crc) = le_u16(input)?;
    match crc16_0x3d65_check(data_header_crc, data_header_buffer, 0) {
        true => {}
        false => {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Verify,
            )))
        }
    };
    Ok((
        input,
        DataLinkLayer {
            length,
            dl_direction,
            dl_primary,
            dl_frame_count_bit,
            dl_frame_count_valid,
            dl_function,
            destination,
            source,
            data_header_crc,
        },
    ))
}

pub fn parse_transport_control(input: &[u8]) -> IResult<&[u8], TransportControl> {
    let (input, (tr_final, tr_first, tr_sequence)) =
        peek(bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
            tuple((take_bits(1usize), take_bits(1usize), take_bits(6usize))),
        ))(input)?;
    Ok((
        input,
        TransportControl {
            tr_final,
            tr_first,
            tr_sequence,
        },
    ))
}

pub fn parse_data_chunk(input: &[u8], check_size: u8) -> IResult<&[u8], &[u8]> {
    let (input, data_chunk) = take(check_size as usize)(input)?;
    let (input, data_chunk_checksum) = le_u16(input)?;
    match crc16_0x3d65_check(data_chunk_checksum, data_chunk, 0) {
        true => {}
        false => {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Verify,
            )))
        }
    };
    Ok((input, data_chunk))
}

pub fn parse_data_chunks(input: &[u8], length: u8) -> IResult<&[u8], Vec<u8>> {
    // if dl_function != 0x09 && dl_function != 0x0B && dl_function != 0x00

    if !(length >= 5) {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Verify,
        )));
    }

    let mut input = input;
    let mut data_len = length - 5; // data_link
    let mut data_chunks: Vec<u8> = Vec::new();
    let mut _data_chunk: &[u8];

    while data_len > 0 {
        let check_size: u8 = std::cmp::min(data_len, 16);
        (input, _data_chunk) = parse_data_chunk(input, check_size)?;
        data_chunks.extend_from_slice(_data_chunk);
        data_len -= check_size;
    }
    Ok((input, data_chunks))
}

pub fn parse_dnp3_application_layer<'a>(
    input: &'a [u8],
    dl_length: u8,
) -> IResult<&'a [u8], Dnp3ApplicationLayer> {
    let (input, data_chunks) = parse_data_chunks(input, dl_length)?;

    let mut data_bytes = data_chunks.as_slice();
    data_bytes = &data_bytes[1..]; // ignore transport_control

    let (data_bytes, app_control) =
        u8::<_, nom::error::Error<&[u8]>>(data_bytes).map_err(|_| {
            nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
        })?;

    let (_data_bytes, function_code) =
        u8::<_, nom::error::Error<&[u8]>>(data_bytes).map_err(|_| {
            nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
        })?;

    // tracing::trace!("app_control: {:x?}, function_code: {:x?}, remain: {:x?}", app_control, function_code, data_bytes);

    // TODO: parsing objects & points
    let app_data = match function_code {
        0x00 => Dnp3ApplicationData::Confirm {},
        0x01 => Dnp3ApplicationData::Read { objects: vec![] },
        0x02 => Dnp3ApplicationData::Write { objects: vec![] },
        0x03 => Dnp3ApplicationData::Select { objects: vec![] },
        0x0d => Dnp3ApplicationData::ColdRestart {},
        0x0e => Dnp3ApplicationData::WarmRestart {},
        0x12 => Dnp3ApplicationData::StopApplication {},
        0x14 => Dnp3ApplicationData::EnableSpontaneousMessage { objects: vec![] },
        0x15 => Dnp3ApplicationData::DisableSpontaneousMessage { objects: vec![] },
        0x19 => Dnp3ApplicationData::OpenFile { objects: vec![] },
        0x81 => Dnp3ApplicationData::Response {
            internal_indications: 0,
            objects: vec![],
        },
        0x82 => Dnp3ApplicationData::UnsolicitedResponse {
            internal_indications: 0,
            objects: vec![],
        },
        _ => {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Verify,
            )))
        }
    };

    Ok((
        input,
        Dnp3ApplicationLayer {
            app_control,
            function_code,
            app_data,
        },
    ))
}
