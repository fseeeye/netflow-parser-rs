use nom::error::{ErrorKind, ParseError};
use thiserror::Error;

/// suricata 规则解析错误
///
/// 实现参考自 [nom - examplecustom_error.rs](https://github.com/Geal/nom/blob/main/examples/custom_error.rs)
#[derive(Error, Debug, PartialEq)]
pub enum SuruleParseError {
    #[error("encountered error while reading the file: '{0}'")]
    FilepathError(String),
    #[error(
        "unterminated value of rule option. Please confirm your suricata rule write in one line."
    )]
    UnterminatedRuleOptionValue,
    #[error(
        "unterminated name of rule option. Please confirm your suricata rule write in one line."
    )]
    UnterminatedRuleOptionName,
    #[error("get an empty str.")]
    EmptyStr,
    #[error("not a list.")]
    NotList,
    #[error("the limit depth of list is 2!")]
    ListDeepthOverflow,
    #[error("unterminated list.")]
    UnterminatedList,
    #[error("encountered error while parsing header tuple: '{0}'")]
    HeaderError(String),
    #[error("invalid list: '{0}'")]
    InvalidList(String),
    #[error("unterminated suricata rule, remain str: '{0}'")]
    UnterminatedRule(String),
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
    #[error("find odd length hex in content pattern: '{0}'")]
    OddContentPatternHex(String),
    #[error("find a wild content modifier which not pointing to any content: '{0}'")]
    WildContentModifier(String),
    #[error("relative keywords (within/distance) & abosolute keywords (depth/offset) & startswith/endswith can't exit in the same content.")]
    ConflictContentModifier,
    #[error("find repeated content modifier: '{0}'")]
    DuplicatedContentModifier(String),
    #[error("unknow flow option: '{0}'")]
    UnknownFlowOption(String),
    #[error("flowbit error: '{0}'")]
    Flowbit(String),
    // 未处理的 Nom 错误类型，不含其 input 信息
    #[error("nom error")]
    UnhandledNomError(ErrorKind),
    // 尝试把私有的 rule element 转换成公有的 rule option 的错误
    // #[error("attempt convert an internal rule element to a public rule option.")]
    // PrivateElement(String),
    // 其它一些不关键的错误集合
    // #[error("other error.")]
    // Other(String),
}

// 实现 nom::error::ParseError trait，这样就能够作为 IResult nom::Err:Error 中的错误类型
// refs: https://github.com/Geal/nom/blob/main/doc/error_management.md
impl<I> ParseError<I> for SuruleParseError {
    fn from_error_kind(_input: I, kind: ErrorKind) -> Self {
        SuruleParseError::UnhandledNomError(kind)
    }

    fn append(_input: I, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl Into<nom::Err<SuruleParseError>> for SuruleParseError {
    fn into(self) -> nom::Err<SuruleParseError> {
        nom::Err::Error(self)
    }
}

impl From<nom::Err<SuruleParseError>> for SuruleParseError {
    fn from(nom_err: nom::Err<SuruleParseError>) -> Self {
        match nom_err {
            nom::Err::Error(e) => return e,
            nom::Err::Failure(e) => return e,
            nom::Err::Incomplete(_) => {
                return SuruleParseError::UnhandledNomError(nom::error::ErrorKind::Fail)
            }
        }
    }
}
