use nom::number::complete::{be_u16};

// use crate::errors::ParseError;
use crate::layer_type::LayerType;
use crate::{Header, Layer};

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl Header for UdpHeader {
    fn get_payload(&self) -> Option<LayerType> {
        unimplemented!()
    }
}

pub fn parse_udp_layer(input: &[u8]) -> nom::IResult<&[u8], (Layer, Option<LayerType>)> {
    let (input, header) = parse_udp_header(input)?;
    let next = header.get_payload();
    let layer = Layer::Udp(header);

    Ok((
        input,
        (
            layer,
            next
        )
    ))
}

pub fn parse_udp_header(input: &[u8]) -> nom::IResult<&[u8], UdpHeader> {
    let (input, src_port) = be_u16(input)?;
    let (input, dst_port) = be_u16(input)?;
    let (input, length) = be_u16(input)?;
    let (input, checksum) = be_u16(input)?;
    Ok((
        input,
        UdpHeader {
            src_port,
            dst_port,
            length,
            checksum,
        },
    ))
}

// fn parse_udp_payload(
//     _input: &[u8],
//     _header: &UdpHeader,
// ) -> Option<LayerType> {
//     unimplemented!();
// }