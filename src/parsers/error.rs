use crate::{layer::Layer, LayerType};

pub fn parse_error_layer(input: &[u8]) -> nom::IResult<&[u8], (Layer, Option<LayerType>)> {
    Ok((&[], (Layer::Error(input), None)))
}
