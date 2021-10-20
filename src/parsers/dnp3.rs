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
use crate::utils::*;

#[allow(unused)]
use std::ops::BitAnd;
#[allow(unused)]
use std::ops::BitOr;
#[allow(unused)]
use std::ops::BitXor;


use super::parse_l5_eof_layer;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Dnp3Header<'a> {
    pub data_link_layer: DataLinkLayer,
    pub transport_control: TransportControl,
    pub data_chunks: DataChunks<'a>,
}

pub fn parse_dnp3_header(input: &[u8]) -> IResult<&[u8], Dnp3Header> {
    let (input, data_link_layer) = parse_data_link_layer(input)?;
    let (input, transport_control) = parse_transport_control(input)?;
    let (input, data_chunks) = parse_data_chunks(input, data_link_layer.dl_function, data_link_layer.length)?;
    Ok((
        input,
        Dnp3Header {
            data_link_layer,
            transport_control,
            data_chunks
        }
    ))
}

pub(crate) fn parse_dnp3_layer<'a>(input: &'a [u8], link_layer: LinkLayer, network_layer: NetworkLayer<'a>, transport_layer: TransportLayer<'a>, options: &QuinPacketOptions) -> QuinPacket<'a> {
    let current_layertype = LayerType::Application(ApplicationLayerType::Dnp3);

    let (input, dnp3_header) = match parse_dnp3_header(input) {
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
        let application_layer = ApplicationLayer::Dnp3(dnp3_header);
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

    let application_layer = ApplicationLayer::Dnp3(dnp3_header);
    return parse_l5_eof_layer(input, link_layer, network_layer, transport_layer, application_layer, options);
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
pub struct DataChunk<'a> {
    pub data_chunk: &'a [u8],
    pub data_chunk_checksum: u16,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DataChunks<'a> {
    WithData {
         data_chunks: Vec<DataChunk<'a>>,
    },
    WithoutData {
        
    }
}

pub fn parse_data_link_layer(input: &[u8]) -> IResult<&[u8], DataLinkLayer> {
    let (input, data_header_buffer) = peek(take(8usize))(input)?;
    let (input, _) = tag::<_,_,nom::error::Error<&[u8]>>([0x05, 0x64])(input)?;
    let (input, length) = u8(input)?;
    let (input, (dl_direction, dl_primary, dl_frame_count_bit, dl_frame_count_valid, dl_function)) = bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
        tuple((take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(1usize), take_bits(4usize)))
    )(input)?;
    let (input, destination) = le_u16(input)?;
    let (input, source) = le_u16(input)?;
    let (input, data_header_crc) = le_u16(input)?;
    match crc16_0x3d65_check(data_header_crc, data_header_buffer, 0) {
        true => {},
        false => {
            return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
        }
    };
    Ok((
        input,
        DataLinkLayer {
            length,
            dl_direction, dl_primary, dl_frame_count_bit, dl_frame_count_valid, dl_function,
            destination,
            source,
            data_header_crc
        }
    ))
}

pub fn parse_transport_control(input: &[u8]) -> IResult<&[u8], TransportControl> {
    let (input, (tr_final, tr_first, tr_sequence)) = peek(bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(
        tuple((take_bits(1usize), take_bits(1usize), take_bits(6usize)))
    ))(input)?;
    Ok((
        input,
        TransportControl {
            tr_final, tr_first, tr_sequence
        }
    ))
}

pub fn parse_data_chunk(input: &[u8], check_size: u8) -> IResult<&[u8], DataChunk> {
    let (input, data_chunk) = take(check_size as usize)(input)?;
    let (input, data_chunk_checksum) = le_u16(input)?;
    match crc16_0x3d65_check(data_chunk_checksum, data_chunk, 0) {
        true => {},
        false => {
            return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
        }
    };
    Ok((
        input,
        DataChunk {
            data_chunk,
            data_chunk_checksum
        }
    ))
}



pub fn parse_data_chunks(input: &[u8], dl_function: u8, length: u8) -> IResult<&[u8], DataChunks> {
    if dl_function != 0x09 && dl_function != 0x0B && dl_function != 0x00 {
        if !(length >= 5) {
            return Err(nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Verify)))
        }
        
        let mut input = input;
        let mut data_len = length - 5;
        let mut data_chunks: Vec<DataChunk> = Vec::new();
        let mut _data_chunk: DataChunk;
        
        while data_len > 0 {
            let check_size: u8 = std::cmp::min(data_len, 16);
            (input, _data_chunk) = parse_data_chunk(input, check_size)?;
            data_chunks.push(_data_chunk);
            data_len -= check_size;
        }
        Ok((
            input,
            DataChunks::WithData {
                data_chunks
            }
        ))
    }
    else {
        Ok((
            input,
            DataChunks::WithoutData {
                
            }
        ))
    }
}