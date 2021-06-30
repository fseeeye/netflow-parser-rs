use nom::combinator::eof;

use super::parser_context::ParserContext; // added

#[derive(Debug, PartialEq)]
pub enum Eof<'a> {
    End(&'a [u8]),
}

impl<'a> Eof<'a> {
    pub fn parse(input: &'a [u8], _context: &mut ParserContext) -> nom::IResult<&'a [u8], Self> {
        match eof(input) {
            Ok((input, nullstr)) => Ok((input, Eof::End(nullstr))),
            Err(e) => Err(e),
            _ => Err(nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::NonEmpty)))
        }
    }
}