use crate::parsers::parser_context::ParserContext;

pub trait PacketTrait<'a>: Sized {
    type Header;
    type Payload;
    type PayloadError; // not neccesary

    fn parse_header(input: &'a [u8], context: &mut ParserContext) -> nom::IResult<&'a [u8], Self::Header>;
    fn parse_payload(input: &'a [u8], header: &Self::Header, context: &mut ParserContext) -> nom::IResult<&'a [u8], Self::Payload>;
    fn parse(input: &'a [u8], context: &mut ParserContext) -> nom::IResult<&'a [u8], Self>;
}
