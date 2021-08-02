use std::net::Ipv4Addr;
use std::convert::TryFrom;

use nom::bits::bits;
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::take;
use nom::number::complete::{be_u16, u8};
use nom::sequence::tuple;

use crate::errors::ParseError;
use crate::layer_type::LayerType;
use crate::{Header, Layer};

#[derive(Debug, PartialEq, Clone)]
pub struct Ipv4Options {
    pub copied: u8,
    pub option_class: u8,
    pub option_type: u8,
    pub option_length: Option<u8>,
    pub option_data: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq, Clone)]
pub enum Ipv4OptionType {
    EOOL,
    NOP,
    SSR,
    Unknow,
}

impl From<u8> for Ipv4OptionType {
    fn from(raw: u8) -> Self {
        match raw {
            0x00 => Ipv4OptionType::EOOL,
            0x01 => Ipv4OptionType::NOP,
            0x89 => Ipv4OptionType::SSR,
            _ => Ipv4OptionType::Unknow,
        }
    }
}

// refs: https://en.wikipedia.org/wiki/IPv4
// refs: https://github.com/seladb/PcapPlusPlus/blob/master/Packet%2B%2B/header/IPv4Layer.h
// refs: https://github.com/google/gopacket/blob/3eaba08943250fd212520e5cff00ed808b8fc60a/layers/ip4.go#L240
fn parse_options(input: &[u8], mut length: usize) -> nom::IResult<&[u8], Option<Vec<Ipv4Options>>> {
    let mut options = Vec::new();
    let mut inner_input = input;

    while length > 0 {
        let (input, (copied, option_class, option_type)): (&[u8], (u8, u8, u8)) =
            bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
                take_bits(1usize),
                take_bits(2usize),
                take_bits(5usize),
            )))(inner_input)?;
        
        let option_length = None;
        let option_data = None;

        match option_type.into() {
            Ipv4OptionType::EOOL => {
                options.push(Ipv4Options {
                    copied,
                    option_class,
                    option_type,
                    option_length,
                    option_data,
                });
                length -= 1;
                break;
            },
            Ipv4OptionType::NOP => {
                options.push(Ipv4Options {
                    copied,
                    option_class,
                    option_type,
                    option_length,
                    option_data,
                });
                length -= 1;
            },
            Ipv4OptionType::Unknow => {
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Verify,
                )))
            }
            _ => {
                let (input, option_length) = u8(inner_input)?;
                length -= 1 as usize;
                let (input, option_data) = take(option_length)(input)?;
                length -= option_length as usize;
                options.push(Ipv4Options {
                    copied,
                    option_class,
                    option_type,
                    option_length: Some(option_length),
                    option_data: Some(option_data.to_vec()),
                });
                inner_input = input;
            }
        }
    }

    Ok((inner_input, Some(options)))
}

#[derive(Debug, PartialEq, Clone)]
pub struct Ipv4Header {
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
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub options: Option<Vec<Ipv4Options>>,
}

impl<'a> Header for Ipv4Header {
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
    let (input, src_ip) = address4(input)?;
    let (input, dst_ip) = address4(input)?;
    // let (input, options) = if (header_length * 4) > 20 {
    //     let (input, options) = take(header_length * 4 - 20)(input)?;
    //     Ok((input, Some(options)))
    // } else {
    //     Ok((input, None))
    // }?;
    let (input, options) = if (header_length * 4) > 20 {
        parse_options(input, (header_length * 4 - 20) as usize)
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

fn address4(input: &[u8]) -> nom::IResult<&[u8], Ipv4Addr> {
    let (input, ipv4_addr) = take(4u8)(input)?;

    Ok((input, Ipv4Addr::from(<[u8; 4]>::try_from(ipv4_addr).unwrap())))
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
