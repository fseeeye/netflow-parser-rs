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
    // Value, 
    ByteJump(elements::ByteJump),
    // Value, Meta Keyword
    Classtype(String),
    // Value, 
    Content(elements::Content),
    // Value, 
    Depth(u64),
    // Value, 
    Dsize(String),
    // Value, 
    Distance(elements::Distance),
    // Bool, 
    EndsWith(bool),
    // Bool, 
    FastPattern(bool),
    // Bool, 
    FileData(elements::FileData),
    // Value, Flow Keywords
    Flow(String),
    // Value, Flow Keywords
    Flowbits(elements::Flowbits),
    // Bool, 
    FtpBounce(bool),
    // Value, 
    IsDataAt(String),
    // Value, Meta Keyword
    Message(String),
    // Value, Meta Keyword
    Metadata(String),
    // Bool, 
    NoAlert(bool),
    // Bool, 
    NoCase(bool),
    // Value, 
    Offset(u64),
    // Value, 
    Pcre(String),
    // Bool, 
    RawBytes(bool),
    // Value, Meta Keyword
    Reference(String),
    // Value, Meta Keyword
    Rev(u64),
    // Value, Meta Keyword
    Sid(u64),
    // Bool, 
    StartsWith(bool),
    // Value, 
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
