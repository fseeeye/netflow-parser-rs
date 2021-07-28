use crate::layer_type::LayerType;
use crate::{Header, Layer};

#[derive(Debug, PartialEq, Clone)]
pub struct EofHeader;

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
    Ok((input, EofHeader{}))
}

// fn parse_eof_payload(
//     input: &[u8],
//     _header: &EofHeader,
// ) -> Option<LayerType> {
//     match eof::<_, (_, _)>(input) {
//         Ok((_input, _nullstr)) => None,
//         Err(_) => Some(LayerType::Error(ParseError::NotEndPayload)),
//     }
// }