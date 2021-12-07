//! Option 表示 Suricata Rule 的可选字段，本模块包含其数据结构以及 parser 的定义。
mod parser;

pub(crate) use parser::parse_option_from_stream;


use super::elements;
use serde::{Deserialize, Serialize};

/// SuruleOption 是包含 Suricata Body Optional Elements 的枚举结构体，用于存储 Suricata 可选字段的数据类型。
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
// #[repr(u16)]
pub enum SuruleOption {
    /* Body Base Option */
    Meta(SuruleMetaOption),
    Payload(SurulePayloadOption),
    Flow(SuruleFlowOption),
    Other(SuruleOtherOption),

    /* Protocol Spec Option */
    HTTP(SuruleHttpOption),
    TCP(SuruleTcpOption),
    UDP(SuruleUdpOption),
    
    /* Unknow Option Element */
    Generic(elements::GenericOption),
}

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Debug, PartialEq)]
// #[repr(u16)]
pub enum SuruleMetaOption {
    // Value, Meta Keyword
    Classtype(String),
    // Value, Meta Keyword
    Message(String),
    // Value, Meta Keyword
    Metadata(String),
    // Value, Meta Keyword
    Reference(String),
    // Value, Meta Keyword
    Rev(u64),
    // Value, Meta Keyword
    Sid(u64),
}

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Debug, PartialEq)]
// #[repr(u16)]
pub enum SurulePayloadOption {
    // Value, Payload Keyword
    ByteJump(elements::ByteJump),
    // Value, Payload Keyword
    Content(elements::Content),
    // Value, Payload Keyword
    Depth(u64),
    // Value, Payload Keyword
    Dsize(String),
    // Value, Payload Keyword
    Distance(elements::Distance),
    // Bool, Payload Keyword
    EndsWith(bool),
    // Value, Payload Keyword
    IsDataAt(String),
    // Bool, Payload Keyword
    NoCase(bool),
    // Value, Payload Keyword
    Offset(u64),
    // Value, Payload Keyword
    Pcre(String),
    // Bool,  Payload Keyword
    RawBytes(bool),
    // Bool,  Payload Keyword
    StartsWith(bool),
    // Value, Payload Keyword
    Within(elements::Within),
}

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Debug, PartialEq)]
// #[repr(u16)]
pub enum SuruleFlowOption {
    // Value, Flow Keyword
    Flow(elements::Flow),
    // Value, Flow Keyword
    Flowbits(elements::Flowbits),
}

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Debug, PartialEq)]
// #[repr(u16)]
pub enum SuruleHttpOption {
    // Bool,  HTTP Keyword
    FileData(elements::FileData),
}

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Debug, PartialEq)]
// #[repr(u16)]
pub enum SuruleTcpOption {
    // TODO
}

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Debug, PartialEq)]
// #[repr(u16)]
pub enum SuruleUdpOption {
    // TODO
}

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Debug, PartialEq)]
// #[repr(u16)]
pub enum SuruleOtherOption {
    // Bool,  Prefiltering Keyword
    FastPattern(bool),
    // Bool, FTP Keyword
    FtpBounce(bool),
    // Bool,  Unknow
    NoAlert(bool),
}
