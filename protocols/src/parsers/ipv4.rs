use nom::bits::bits;
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::take;
use nom::number::complete::{be_u16, be_u32, u8};
use nom::sequence::tuple;

use crate::errors::ParseError;
use crate::layer_type::LayerType;
use crate::{Header, Layer};

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Ipv4Header<'a> {
    pub version: u8,
    pub header_length: u8,
    pub diff_service: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub id: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub options: Option<&'a [u8]>,
}

impl<'a> Header for Ipv4Header<'a> {
    fn get_payload(&self) -> Option<LayerType> {
        match self.protocol {
            0x06 => Some(LayerType::Tcp),
            0x11 => Some(LayerType::Udp),
            _ => Some(LayerType::Error(ParseError::UnknownPayload)),
        }
    }
}

pub fn parse_ipv4_layer(input: &[u8]) -> nom::IResult<&[u8], (Layer, Option<LayerType>)> {
    let (input, header) = parse_ipv4_header(input)?;
    let next = header.get_payload();
    let layer = Layer::Ipv4(header);

    Ok((
        input,
        (
            layer,
            next
        )
    ))
}

pub fn parse_ipv4_header(input: &[u8]) -> nom::IResult<&[u8], Ipv4Header> {
    let (input, (version, header_length, diff_service, ecn)) =
        bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
            take_bits(4usize),
            take_bits(4usize),
            take_bits(6usize),
            take_bits(2usize),
        )))(input)?;
    let (input, total_length) = be_u16(input)?;
    let (input, id) = be_u16(input)?;
    let (input, (flags, fragment_offset)) =
        bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
            take_bits(3usize),
            take_bits(13usize),
        )))(input)?;
    let (input, ttl) = u8(input)?;
    let (input, protocol) = u8(input)?;
    let (input, checksum) = be_u16(input)?;
    let (input, src_ip) = be_u32(input)?;
    let (input, dst_ip) = be_u32(input)?;
    let (input, options) = if (header_length * 4) > 20 {
        let (input, options) = take(header_length * 4 - 20)(input)?;
        Ok((input, Some(options)))
    } else {
        Ok((input, None))
    }?;
    Ok((
        input,
        Ipv4Header {
            version,
            header_length,
            diff_service,
            ecn,
            total_length,
            id,
            flags,
            fragment_offset,
            ttl,
            protocol,
            checksum,
            src_ip,
            dst_ip,
            options,
        },
    ))
}

// // ref: https://www.ietf.org/rfc/rfc790.txt
// fn parse_ipv4_payload(
//     input: &[u8],
//     _header: &Ipv4Header,
// ) -> Option<LayerType> {
//     match input.len() {
//         0 => Some(LayerType::Eof),
//         _ => match _header.protocol {
//             0x06 => Some(LayerType::Tcp),
//             0x11 => Some(LayerType::Udp),
//             _ => Some(LayerType::Error(ParseError::UnknownPayload)),
//         },
//     }
// }
