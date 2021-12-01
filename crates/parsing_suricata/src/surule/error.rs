use nom::error::{ErrorKind, ParseError};
use thiserror::Error;

/// suricata 规则解析错误
///
/// 实现参考自 [nom - examplecustom_error.rs](https://github.com/Geal/nom/blob/main/examples/custom_error.rs)
#[derive(Error, Debug, PartialEq)]
pub enum SuruleParseError<I> {
    #[error("get an empty str.")]
    EmptyStr,
    #[error("not a list.")]
    NotList,
    #[error("the limit depth of list is 2!")]
    ListDeepthOverflow,
    #[error("unterminated list.")]
    UnterminatedList,
    #[error("invalid list: '{0}'")]
    InvalidList(String),
    #[error("unterminated value of rule option.")]
    UnterminatedRuleOptionValue,
    #[error("unterminated name of rule option.")]
    UnterminatedRuleOptionName,
    #[error("encountered error while taking action str: '{0}'")]
    NoAction(String),
    #[error("invalid action str: '{0}'")]
    InvalidAction(String),
    #[error("encountered error while taking protocol str: '{0}'")]
    NoProtocol(String),
    #[error("invalid protocol str: '{0}'")]
    InvalidProtocol(String),
    #[error("invalid ip address: '{0}'")]
    InvalidIpAddr(String),
    #[error("invalid port range: '{0}'")]
    InvalidPort(String),
    #[error("don't find option staring backet")]
    NoOptionElement,
    #[error("sid parsing error: '{0}'")]
    InvalidSid(String),
    #[error("direction parsing error: '{0}'")]
    InvalidDirection(String),
    #[error("byte jump parsing error: '{0}'")]
    InvalidByteJump(String),
    #[error("integer parsing error: '{0}'")]
    IntegerParseError(String),
    #[error("flowbit error: '{0}'")]
    Flowbit(String),
    // Nom 错误类型
    #[error("nom error: {1:?}({0:?})")]
    Nom(I, ErrorKind),
    // 尝试把私有的 rule element 转换成公有的 rule option 的错误
    // #[error("attempt convert an internal rule element to a public rule option.")]
    // PrivateElement(String),
    // 其它一些不关键的错误集合
    // #[error("other error.")]
    // Other(String),
}

// 实现 nom::error::ParseError trait，这样就能够作为 IResult nom::Err:Error 中的错误类型
// refs: https://github.com/Geal/nom/blob/main/doc/error_management.md
impl<I> ParseError<I> for SuruleParseError<I> {
    fn from_error_kind(input: I, kind: ErrorKind) -> Self {
        SuruleParseError::Nom(input, kind)
    }

    fn append(_input: I, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<I> Into<nom::Err<SuruleParseError<I>>> for SuruleParseError<I> {
    fn into(self) -> nom::Err<SuruleParseError<I>> {
        nom::Err::Error(self)
    }
}
