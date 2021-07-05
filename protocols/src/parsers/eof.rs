use nom::combinator::eof;
use nom::Err;
use nom::error::{Error, ErrorKind};

#[derive(Debug, PartialEq)]
pub enum EofPacket<'a> {
    End(),
    NotEnd(&'a [u8])
}

pub fn parse_eof_packet(input: &[u8]) -> nom::IResult<&[u8], EofPacket> {
    match eof(input) {
        Ok((input, _nullstr)) => Ok((input, EofPacket::End())),
        Err(Err::Error((input, _))) => Ok((input, EofPacket::NotEnd(input))),
        _ => Err(Err::Failure(Error::new(input, ErrorKind::Verify)))
    }
}