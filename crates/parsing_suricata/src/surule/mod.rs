//! 解析 suricata 规则字符串
//!
//! 解析得到的 Surule 数据结构支持序列化/反序列化，可以简单地撰写程序将该规则转换成 Json / YAML 格式。
mod element_parser;
mod error;
mod surule_parser;
mod types;
mod utils;

pub use error::SuruleParseError;
pub use surule_parser::parse_suricata_rule;


#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct Surule {
    action: String,
    protocol: String,
    src_addr: String,
    src_port: String,
    direction: types::Direction,
    dst_addr: String,
    dst_port: String,
    options: Vec<SuruleElement>,
}

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(rename_all = "snake_case")
)]
#[derive(Clone, Debug, PartialEq)]
#[repr(u16)]
pub enum SuruleElement {
    // // Header (Considered) Elements:
    // Actions(String),
    // Protocol(String),
    // SrcAddr(String),
    // SrcPort(String),
    // Direction(types::Direction),
    // DstAddr(String),
    // DstPort(String),

    // Body (Option) Elements:
    ByteJump(types::ByteJump),
    Classtype(String),
    Content(types::Content),
    Depth(u64),
    Dsize(String),
    Distance(types::Distance),
    EndsWith(bool),
    FastPattern(bool),
    FileData(types::FileData),
    Flow(String),
    Flowbits(types::Flowbits),
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
    Within(types::Within),

    // Unknow Element
    GenericOption(types::GenericOption),
}

impl From<&str> for SuruleElement {
    // 解析不含值的option字段，可以通过 &str 直接转换为 SuruleElement
    fn from(name_str: &str) -> Self {
        match name_str {
            "endswith" => Self::EndsWith(true),
            "fast_pattern" => Self::FastPattern(true),
            "file_data" => Self::FileData(types::FileData),
            "ftpbounce" => Self::FtpBounce(true),
            "noalert" => Self::NoAlert(true),
            "nocase" => Self::NoCase(true),
            "rawbytes" => Self::RawBytes(true),
            "startswith" => Self::StartsWith(true),
            _ => Self::GenericOption(types::GenericOption {
                name: name_str.to_string(),
                val: None,
            }),
        }
    }
}
