use nom::error::{ErrorKind, ParseError};
use thiserror::Error;

/// suricata 规则解析错误
/// 
/// 实现参考自 [nom - examplecustom_error.rs](https://github.com/Geal/nom/blob/main/examples/custom_error.rs)
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum SuruleParseError<I> {
    #[error("get an empty str.")]
    EmptyStr,
    #[error("not a list.")]
    NotList,
    #[error("input is an unterminated list.")]
    UnterminatedList,
    #[error("input is an unterminated rule option value.")]
    UnterminatedRuleOptionValue,
    #[error("")]
    InvalidSid(String),
    #[error("")]
    InvalidDirection(String),
    #[error("")]
    InvalidByteJump(String),
    #[error("")]
    IntegerParseError(String),
    #[error("")]
    Flowbit(String),
    // 尝试把私有的 rule element 转换成公有的 rule option 的错误
    #[error("")]
    PrivateElement(String),
    // 其它一些不关键的错误集合
    #[error("")]
    Other(String),
    // Nom 错误类型
    #[error("")]
    Nom(I, ErrorKind)
}

// 实现 nom::error::ParseError trait，这样就能够作为 IResult nom::Err:Error 中的错误类型
impl<I> ParseError<I> for SuruleParseError<I> {
    fn from_error_kind(input: I, kind: ErrorKind) -> Self {
        SuruleParseError::Nom(input, kind)
    }

    fn append(_input: I, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}