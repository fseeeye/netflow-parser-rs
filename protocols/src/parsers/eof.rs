use nom::combinator::eof;

use crate::layer_type::LayerType;
use crate::{Header, Layer};

#[derive(Debug, PartialEq, Clone)]
pub struct EofHeader {
    pub end: bool,
}

impl Header for EofHeader {
    fn get_payload(&self) -> Option<LayerType> {
        None
    }
}

pub fn parse_eof_layer(input: &[u8]) -> nom::IResult<&[u8], (Layer, Option<LayerType>)> {
    let (input, header) = parse_eof_header(input)?;
    let next = header.get_payload();
    let layer = Layer::Eof(header);

    Ok((
        input,
        (
            layer,
            next
        )
    ))
}

pub fn parse_eof_header(input: &[u8]) -> nom::IResult<&[u8], EofHeader> {
    match eof::<_, ()>(input) {
        Ok((_input, _nullstr)) => Ok((input, EofHeader{ end: true })),
        Err(_e) => Ok((input, EofHeader{ end: false })),
    }
}