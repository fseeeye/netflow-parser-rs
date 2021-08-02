#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum ParseError<'a> {
    ParsingPayload(&'a [u8]),
    ParsingHeader(&'a [u8]),
    UnknownPayload(&'a [u8]),
    NotEndPayload(&'a [u8]),
    UnregisteredParser(&'a [u8]),
}