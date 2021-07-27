use nom::combinator::eof;
use nom::Err;

use crate::errors::ParseError;
use crate::layer_type::LayerType;
use crate::Layer;

#[derive(Debug, PartialEq, Clone)]
pub struct EofHeader;

pub fn parse_eof_layer(input: &[u8]) -> nom::IResult<&[u8], (Layer, Option<LayerType>)> {
    let (input, header) = parse_eof_header(input)?;
    let next = parse_eof_payload(input, &header);
    let layer = Layer::Eof(header);

    Ok((
        input,
        (
            layer,
            next
        )
    ))
}

fn parse_eof_header(input: &[u8]) -> nom::IResult<&[u8], EofHeader> {
    Ok((input, EofHeader{}))
}

fn parse_eof_payload(
    input: &[u8],
    _header: &EofHeader,
) -> Option<LayerType> {
    match eof(input) {
        Ok((_input, _nullstr)) => None,
        Err(Err::Error((_input, _))) => Some(LayerType::Error(ParseError::NotEndPayload)),
        _ => Some(LayerType::Error(ParseError::ParsingPayload)),
    }
}