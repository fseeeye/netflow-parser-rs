use nom::combinator::eof;
use nom::error::{Error, ErrorKind};
use nom::Err;

use crate::layer_type::LayerType;
use crate::{PacketTrait, HeaderTrait, PayloadTrait};

#[derive(Debug, PartialEq)]
pub struct EofPacket<'a> {
    header: EofHeader,
    payload: EofPayload<'a>,
}

#[derive(Debug, PartialEq)]
pub struct EofHeader;
impl<'a> HeaderTrait<'a> for EofHeader {
    fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        Ok((input, Self{}))
    }

    fn get_type(&self) -> LayerType {
        return LayerType::Eof;
    }
}

#[derive(Debug, PartialEq)]
pub enum EofPayload<'a>{
    End(),
    NotEnd(&'a [u8]),
}

impl<'a> PayloadTrait<'a> for EofPayload<'a> {
    type Header = EofHeader;

    fn parse(
        input: &'a [u8],
        _header: &Self::Header,
    ) -> nom::IResult<&'a [u8], Self> {
        match eof(input) {
            Ok((input, _nullstr)) => Ok((input, Self::End())),
            Err(Err::Error((input, _))) => Ok((input, Self::NotEnd(input))),
            _ => Err(Err::Failure(Error::new(input, ErrorKind::Verify))),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct EofPayloadError;

impl<'a> PacketTrait<'a> for EofPacket<'a> {
    fn parse(input: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (input, header) = EofHeader::parse(input)?;
        let (input, payload) = EofPayload::parse(input, &header)?;
        Ok((input, Self { header, payload }))
    }
}
