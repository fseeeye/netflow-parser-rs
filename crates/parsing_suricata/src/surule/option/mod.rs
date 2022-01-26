//! Option 表示 Suricata Rule 的可选字段，本模块包含其数据结构以及 parser 的定义。
mod parser;

pub(crate) use parser::parse_option_from_stream;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::elements::{self, Content, ContentPosKey};
use crate::SuruleParseError;

/// SuruleOption 是包含 Suricata Body Optional Elements 的枚举结构体，用于存储 Suricata 可选字段的数据类型。
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
// #[repr(u16)]
pub enum SuruleOption {
    /* Body Base Option */
    Meta(SuruleMetaOption),
    Payload(SuruleNaivePayloadOption),
    Flow(SuruleFlowOption),
    Other(SuruleOtherOption),

    /* Protocol Spec Option */
    HTTP(SuruleHttpOption),
    TCP(SuruleTcpOption),
    UDP(SuruleUdpOption),
    FTP(SuruleFtpOption),

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
    Metadata(Vec<String>),
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
pub enum SuruleNaivePayloadOption {
    // Value, Payload Keyword
    ByteJump(elements::ByteJump),
    // Value, Payload Keyword
    ByteTest(elements::ByteTest),
    // Value, Payload Keyword
    Content(elements::Content),
    // Value, Payload Keyword
    Depth(usize),
    // Value, Payload Keyword
    Dsize(elements::Dsize),
    // Value, Payload Keyword
    Distance(isize),
    // Bool, Payload Keyword
    EndsWith,
    // Value, Payload Keyword
    IsDataAt(elements::IsDataAt),
    // Bool, Payload Keyword
    NoCase,
    // Value, Payload Keyword
    Offset(usize),
    // Value, Payload Keyword
    Pcre(elements::Pcre),
    // Bool,  Payload Keyword
    RawBytes,
    // Bool,  Payload Keyword
    StartsWith,
    // Value, Payload Keyword
    Within(usize),
    // Bool,  Prefiltering Keyword
    FastPattern,
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
    ByteTest(elements::ByteTest),
    // Value, Payload Keyword
    Content(elements::Content),
    // Value, Payload Keyword
    Dsize(elements::Dsize),
    // Value, Payload Keyword
    IsDataAt(elements::IsDataAt),
    // Value, Payload Keyword
    Pcre(elements::Pcre),
    // Bool,  Payload Keyword
    RawBytes,
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
pub enum SuruleFtpOption {
    // Bool, FTP Keyword
    FtpBounce,
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
    // Value, Xbits Keyword
    XBits(elements::XBits),
    // Bool,  Unknow
    NoAlert,
}

/// 将 Payload Options 中的 Content 修饰符应用到 Content 上
pub(crate) fn impl_content_modifiers(
    payload_naive_options: Vec<SuruleNaivePayloadOption>,
) -> Result<Vec<SurulePayloadOption>, SuruleParseError> {
    let mut modified_payload_options: Vec<SurulePayloadOption> = Vec::new();
    let mut current_content: Option<Content> = None;

    if payload_naive_options.is_empty() {
        return Ok(modified_payload_options);
    }

    // impl modifiers
    for payload_naive_option in payload_naive_options {
        match payload_naive_option {
            /* Content Keyword & its modifiers */
            SuruleNaivePayloadOption::Content(c) => {
                if let Some(cc) = current_content {
                    modified_payload_options.push(SurulePayloadOption::Content(cc));
                }
                current_content = Some(c);
            }
            SuruleNaivePayloadOption::FastPattern => {
                if let Some(ref mut cc) = current_content {
                    if cc.fast_pattern == false {
                        cc.fast_pattern = true;
                    } else {
                        return Err(SuruleParseError::DuplicatedContentModifier(format!(
                            "fastpattern"
                        )));
                    }
                } else {
                    return Err(SuruleParseError::WildContentModifier(format!(
                        "fastpattern"
                    )));
                }
            }
            SuruleNaivePayloadOption::NoCase => {
                if let Some(ref mut cc) = current_content {
                    if cc.nocase == false {
                        cc.nocase = true;
                    } else {
                        return Err(SuruleParseError::DuplicatedContentModifier(format!(
                            "nocase"
                        )));
                    }
                    cc.pattern.make_ascii_lowercase();
                } else {
                    return Err(SuruleParseError::WildContentModifier(format!("nocase")));
                }
            }
            SuruleNaivePayloadOption::StartsWith => {
                if let Some(ref mut cc) = current_content {
                    match cc.pos_key {
                        ContentPosKey::NotSet => cc.pos_key = ContentPosKey::StartsWith,
                        ContentPosKey::StartsWith => {
                            return Err(SuruleParseError::DuplicatedContentModifier(format!(
                                "startswith"
                            )))
                        }
                        _ => return Err(SuruleParseError::ConflictContentModifier),
                    }
                } else {
                    return Err(SuruleParseError::WildContentModifier(format!("startswith")));
                }
            }
            SuruleNaivePayloadOption::EndsWith => {
                if let Some(ref mut cc) = current_content {
                    match cc.pos_key {
                        ContentPosKey::NotSet => cc.pos_key = ContentPosKey::EndsWith,
                        ContentPosKey::EndsWith => {
                            return Err(SuruleParseError::DuplicatedContentModifier(format!(
                                "endswith"
                            )))
                        }
                        _ => return Err(SuruleParseError::ConflictContentModifier),
                    }
                } else {
                    return Err(SuruleParseError::WildContentModifier(format!("endswith")));
                }
            }
            SuruleNaivePayloadOption::Depth(d) => {
                if let Some(ref mut cc) = current_content {
                    match cc.pos_key {
                        ContentPosKey::NotSet => {
                            cc.pos_key = ContentPosKey::Absolute {
                                depth: Some(d),
                                offset: None,
                            }
                        }
                        ContentPosKey::Absolute { depth, offset } => {
                            if depth.is_some() {
                                return Err(SuruleParseError::DuplicatedContentModifier(format!(
                                    "depth"
                                )));
                            }
                            cc.pos_key = ContentPosKey::Absolute {
                                depth: Some(d),
                                offset,
                            }
                        }
                        _ => return Err(SuruleParseError::ConflictContentModifier),
                    }
                } else {
                    return Err(SuruleParseError::WildContentModifier(format!(
                        "depth:{:?}",
                        d
                    )));
                }
            }
            SuruleNaivePayloadOption::Offset(o) => {
                if let Some(ref mut cc) = current_content {
                    match cc.pos_key {
                        ContentPosKey::NotSet => {
                            cc.pos_key = ContentPosKey::Absolute {
                                depth: None,
                                offset: Some(o),
                            }
                        }
                        ContentPosKey::Absolute { depth, offset } => {
                            if offset != Default::default() {
                                return Err(SuruleParseError::DuplicatedContentModifier(format!(
                                    "offset"
                                )));
                            }
                            cc.pos_key = ContentPosKey::Absolute {
                                depth,
                                offset: Some(o),
                            }
                        }
                        _ => return Err(SuruleParseError::ConflictContentModifier),
                    }
                } else {
                    return Err(SuruleParseError::WildContentModifier(format!(
                        "offset:{:?}",
                        o
                    )));
                }
            }
            SuruleNaivePayloadOption::Within(w) => {
                if let Some(ref mut cc) = current_content {
                    match cc.pos_key {
                        ContentPosKey::NotSet => {
                            cc.pos_key = ContentPosKey::Relative {
                                within: Some(w),
                                distance: None,
                            }
                        }
                        ContentPosKey::Relative { distance, within } => {
                            if within.is_some() {
                                return Err(SuruleParseError::DuplicatedContentModifier(format!(
                                    "within"
                                )));
                            }
                            cc.pos_key = ContentPosKey::Relative {
                                distance: distance,
                                within: Some(w),
                            }
                        }
                        _ => return Err(SuruleParseError::ConflictContentModifier),
                    }
                } else {
                    return Err(SuruleParseError::WildContentModifier(format!(
                        "within:{:?}",
                        w
                    )));
                }
            }
            SuruleNaivePayloadOption::Distance(d) => {
                if let Some(ref mut cc) = current_content {
                    match cc.pos_key {
                        ContentPosKey::NotSet => {
                            cc.pos_key = ContentPosKey::Relative {
                                within: None,
                                distance: Some(d),
                            }
                        }
                        ContentPosKey::Relative { distance, within } => {
                            if distance.is_some() {
                                return Err(SuruleParseError::DuplicatedContentModifier(format!(
                                    "distance"
                                )));
                            }
                            cc.pos_key = ContentPosKey::Relative {
                                distance: Some(d),
                                within: within,
                            }
                        }
                        _ => return Err(SuruleParseError::ConflictContentModifier),
                    }
                } else {
                    return Err(SuruleParseError::WildContentModifier(format!(
                        "distance:{:?}",
                        d
                    )));
                }
            }
            /* Other Payload Keywords */
            SuruleNaivePayloadOption::ByteJump(bj) => {
                if let Some(cc) = current_content {
                    modified_payload_options.push(SurulePayloadOption::Content(cc));
                    current_content = None;
                }
                modified_payload_options.push(SurulePayloadOption::ByteJump(bj))
            }
            SuruleNaivePayloadOption::ByteTest(bt) => {
                if let Some(cc) = current_content {
                    modified_payload_options.push(SurulePayloadOption::Content(cc));
                    current_content = None;
                }
                modified_payload_options.push(SurulePayloadOption::ByteTest(bt))
            }
            SuruleNaivePayloadOption::Dsize(d) => {
                if let Some(cc) = current_content {
                    modified_payload_options.push(SurulePayloadOption::Content(cc));
                    current_content = None;
                }
                modified_payload_options.push(SurulePayloadOption::Dsize(d))
            }
            SuruleNaivePayloadOption::IsDataAt(i) => {
                if let Some(cc) = current_content {
                    modified_payload_options.push(SurulePayloadOption::Content(cc));
                    current_content = None;
                }
                modified_payload_options.push(SurulePayloadOption::IsDataAt(i))
            }
            SuruleNaivePayloadOption::Pcre(p) => {
                if let Some(cc) = current_content {
                    modified_payload_options.push(SurulePayloadOption::Content(cc));
                    current_content = None;
                }
                modified_payload_options.push(SurulePayloadOption::Pcre(p))
            }
            SuruleNaivePayloadOption::RawBytes => {
                // ref: https://suricata.readthedocs.io/en/latest/rules/payload-keywords.html#rawbytes
                // The rawbytes keyword has no effect.
            }
        }
    }

    if let Some(cc) = current_content {
        modified_payload_options.push(SurulePayloadOption::Content(cc));
    }

    Ok(modified_payload_options)
}
