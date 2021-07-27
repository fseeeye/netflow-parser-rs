use nom::bits::bits;
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::take;
use nom::number::complete::{be_u16, u8};
use nom::sequence::tuple;

// use crate::errors::ParseError;
use crate::layer_type::LayerType;
use crate::Layer;

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Ipv6Header<'a> {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_ip: &'a [u8],
    pub dst_ip: &'a [u8],
    pub extension_headers: Option<&'a [u8]>,
}

pub fn parse_ipv6_layer(input: &[u8]) -> nom::IResult<&[u8], (Layer, Option<LayerType>)> {
    let (input, header) = parse_ipv6_header(input)?;
    let next = parse_ipv6_payload(input, &header);
    let layer = Layer::Ipv6(header);

    Ok((
        input,
        (
            layer,
            next
        )
    ))
}

fn parse_ipv6_header(input: &[u8]) -> nom::IResult<&[u8], Ipv6Header> {
    let (input, (version, traffic_class, flow_label)) =
        bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
            take_bits(4usize),
            take_bits(8usize),
            take_bits(20usize),
        )))(input)?;
    let (input, payload_length) = be_u16(input)?;
    let (input, next_header) = u8(input)?;
    let (input, hop_limit) = u8(input)?;
    let (input, src_ip) = take(16usize)(input)?;
    let (input, dst_ip) = take(16usize)(input)?;
    let (input, extension_headers) = if payload_length > 40 {
        let (input, extension_headers) = take(payload_length - 40)(input)?;
        Ok((input, Some(extension_headers)))
    } else {
        Ok((input, None))
    }?;
    Ok((
        input,
        Ipv6Header {
            version,
            traffic_class,
            flow_label,
            payload_length,
            next_header,
            hop_limit,
            src_ip,
            dst_ip,
            extension_headers,
        },
    ))
}

fn parse_ipv6_payload(
    _input: &[u8],
    _header: &Ipv6Header,
) -> Option<LayerType> {
    unimplemented!();
}