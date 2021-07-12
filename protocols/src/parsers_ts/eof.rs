use nom::combinator::eof;
use nom::error::{Error, ErrorKind};
use nom::Err;

#[derive(Debug, PartialEq)]
pub enum EofPacket<'a> {
    End(),
    NotEnd(&'a [u8]),
}

impl<'a> EofPacket<'a> {
    pub fn parse(input: &[u8]) -> nom::IResult<&[u8], EofPacket> {
        match eof(input) {
            Ok((input, _nullstr)) => Ok((input, EofPacket::End())),
            Err(Err::Error((input, _))) => Ok((input, EofPacket::NotEnd(input))),
            _ => Err(Err::Failure(Error::new(input, ErrorKind::Verify))),
        }
    }
}
