#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum ParseError {
    ParsingPayload,
    ParsingHeader,
    UnknownPayload,
    UnregisteredParser,
}