mod parser;

pub(crate) use parser::parse_option_element;

use super::elements;
use serde::{Deserialize, Serialize};

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Debug, PartialEq)]
#[repr(u16)]
pub enum SuruleOption {
    // Body Option Generic Elements:
    ByteJump(elements::ByteJump),
    Classtype(String),
    Content(elements::Content),
    Depth(u64),
    Dsize(String),
    Distance(elements::Distance),
    EndsWith(bool),
    FastPattern(bool),
    FileData(elements::FileData),
    Flow(String),
    Flowbits(elements::Flowbits),
    FtpBounce(bool),
    IsDataAt(String),
    Message(String),
    Metadata(String),
    NoAlert(bool),
    NoCase(bool),
    Offset(u64),
    Pcre(String),
    RawBytes(bool),
    Reference(String),
    Rev(u64),
    Sid(u64),
    StartsWith(bool),
    Within(elements::Within),

    // Unknow Option Element:
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
