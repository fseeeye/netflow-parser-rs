//! Option 表示 Suricata Rule 的可选字段，本模块包含其数据结构以及 parser 的定义。
mod parser;

pub(crate) use parser::parse_option_element;

use super::elements;
use serde::{Deserialize, Serialize};

/// SuruleOption 是包含 Suricata Body (Optional) Elements 的枚举结构体，用于存储 Suricata 可选字段类型的数据。
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Debug, PartialEq)]
#[repr(u16)]
pub enum SuruleOption {
    /* Body Option Generic Elements */
    // Value, Payload Keyword
    ByteJump(elements::ByteJump),
    // Value, Meta Keyword
    Classtype(String),
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
    // Bool, Prefiltering Keyword
    FastPattern(bool),
    // Bool, HTTP Keyword
    FileData(elements::FileData),
    // Value, Flow Keyword
    Flow(elements::Flow),
    // Value, Flow Keyword
    Flowbits(elements::Flowbits),
    // Bool, FTP Keyword
    FtpBounce(bool),
    // Value, Payload Keyword
    IsDataAt(String),
    // Value, Meta Keyword
    Message(String),
    // Value, Meta Keyword
    Metadata(String),
    // Bool, Belong to Flowbit
    NoAlert(bool),
    // Bool, Payload Keyword
    NoCase(bool),
    // Value, Payload Keyword
    Offset(u64),
    // Value, Payload Keyword
    Pcre(String),
    // Bool, Payload Keyword
    RawBytes(bool),
    // Value, Meta Keyword
    Reference(String),
    // Value, Meta Keyword
    Rev(u64),
    // Value, Meta Keyword
    Sid(u64),
    // Bool, Payload Keyword
    StartsWith(bool),
    // Value, Payload Keyword
    Within(elements::Within),

    /* Unknow Option Element */
    GenericOption(elements::GenericOption),
}

impl From<&str> for SuruleOption {
    // 解析不含值的option字段，可以通过 &str 直接转换为 SuruleElement
    fn from(name_str: &str) -> Self {
        match name_str {
            "endswith" => Self::EndsWith(true),
            "fast_pattern" => Self::FastPattern(true),
            "file_data" => Self::FileData(elements::FileData),
            "ftpbounce" => Self::FtpBounce(true),
            "noalert" => Self::NoAlert(true),
            "nocase" => Self::NoCase(true),
            "rawbytes" => Self::RawBytes(true),
            "startswith" => Self::StartsWith(true),
            _ => Self::GenericOption(elements::GenericOption {
                name: name_str.to_string(),
                val: None,
            }),
        }
    }
}
