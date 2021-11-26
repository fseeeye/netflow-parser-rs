use super::types;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct Surule {
    pub action: String,
    pub protocol: String,
    pub src_addr: String,
    pub src_port: String,
    pub direction: types::Direction,
    pub dst_addr: String,
    pub dst_port: String,
    pub options: Vec<SuruleElement>,
}

impl Surule {
    pub fn new(
        action: impl ToString,
        protocol: impl ToString,
        src_addr: impl ToString,
        src_port: impl ToString,
        direction: types::Direction,
        dst_addr: impl ToString,
        dst_port: impl ToString,
        options: Vec<SuruleElement>,
    ) -> Self {
        Self {
            action: action.to_string(),
            protocol: protocol.to_string(),
            src_addr: src_addr.to_string(),
            src_port: src_port.to_string(),
            direction,
            dst_addr: dst_addr.to_string(),
            dst_port: dst_port.to_string(),
            options,
        }
    }
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
