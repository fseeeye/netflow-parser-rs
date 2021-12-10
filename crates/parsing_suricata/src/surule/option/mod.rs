//! Option 表示 Suricata Rule 的可选字段，本模块包含其数据结构以及 parser 的定义。
mod parser;


pub(crate) use parser::parse_option_from_stream;

use serde::{Deserialize, Serialize};
use anyhow::Result;

use crate::SuruleParseError;
use super::elements::{self, Content, ContentPosKey};

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
pub enum SuruleNaivePayloadOption {
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
    // Bool,  Prefiltering Keyword
    FastPattern(bool),
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
    Dsize(String),
    // Value, Payload Keyword
    IsDataAt(String),
    // Value, Payload Keyword
    Pcre(String),
    // Bool,  Payload Keyword
    RawBytes(bool),
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
    // Bool, FTP Keyword
    FtpBounce(bool),
    // Bool,  Unknow
    NoAlert(bool),
}

/// 将 Payload Options 中的 Content 修饰符应用到 Content 上
pub(crate) fn impl_content_modifiers(payload_naive_options: Vec<SuruleNaivePayloadOption>) -> Result<Vec<SurulePayloadOption>, SuruleParseError> {
    let mut modified_payload_options: Vec<SurulePayloadOption> = Vec::new();
    let mut current_content: Option<Content> = None;
    
    if payload_naive_options.is_empty() {
        return Ok(modified_payload_options)
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
            },
            SuruleNaivePayloadOption::FastPattern(f) => {
                if let Some(ref mut cc) = current_content {
                    cc.fast_pattern = f;
                } else {
                    return Err(SuruleParseError::WildContentModifier(format!("fastpattern:{:?}", f)))
                }
            },
            SuruleNaivePayloadOption::NoCase(n) => {
                if let Some(ref mut cc) = current_content {
                    cc.nocase = n;
                } else {
                    return Err(SuruleParseError::WildContentModifier(format!("nocase:{:?}", n)))
                }
            },
            SuruleNaivePayloadOption::Depth(d) => {
                if let Some(ref mut cc) = current_content {
                    match cc.pos_key {
                        ContentPosKey::NotSet => {
                            cc.pos_key = ContentPosKey::Absolute {
                                depth: d,
                                offset: Default::default()
                            }
                        },
                        ContentPosKey::Absolute { depth, offset } => {
                            if depth != Default::default() {
                                return Err(SuruleParseError::DuplicatedContentModifier("depth".to_string()))
                            }
                            cc.pos_key = ContentPosKey::Absolute {
                                depth: d,
                                offset
                            }
                        },
                        _ => {
                            return Err(SuruleParseError::ConflictContentModifier)
                        }
                    }
                } else {
                    return Err(SuruleParseError::WildContentModifier(format!("depth:{:?}", d)))
                }
            },
            SuruleNaivePayloadOption::Distance(d) => {
                if let Some(ref mut cc) = current_content {
                    match cc.pos_key {
                        ContentPosKey::NotSet => {
                            cc.pos_key = ContentPosKey::Relative {
                                distance: d,
                                within: Default::default()
                            }
                        },
                        ContentPosKey::Relative { ref distance, ref within} => {
                            if *distance != Default::default() {
                                return Err(SuruleParseError::DuplicatedContentModifier("distance".to_string()))
                            }
                            cc.pos_key = ContentPosKey::Relative {
                                distance: d,
                                within: within.to_owned()
                            }
                        },
                        _ => {
                            return Err(SuruleParseError::ConflictContentModifier)
                        }
                    }
                } else {
                    return Err(SuruleParseError::WildContentModifier(format!("distance:{:?}", d)))
                }
            },
            SuruleNaivePayloadOption::EndsWith(e) => {
                if let Some(ref mut cc) = current_content {
                    match cc.pos_key {
                        ContentPosKey::NotSet => {
                            cc.pos_key = ContentPosKey::EndsWith(e)
                        },
                        ContentPosKey::EndsWith(_) => {
                            return Err(SuruleParseError::DuplicatedContentModifier("endswith".to_string()))
                        }
                        _ => {
                            return Err(SuruleParseError::ConflictContentModifier)
                        }
                    }
                } else {
                    return Err(SuruleParseError::WildContentModifier(format!("endswith:{:?}", e)))
                }
            },
            SuruleNaivePayloadOption::Offset(o) => {
                if let Some(ref mut cc) = current_content {
                    match cc.pos_key {
                        ContentPosKey::NotSet => {
                            cc.pos_key = ContentPosKey::Absolute {
                                depth: Default::default(),
                                offset: o
                            }
                        },
                        ContentPosKey::Absolute {depth, offset } => {
                            if offset != Default::default() {
                                return Err(SuruleParseError::DuplicatedContentModifier("offset".to_string()))
                            }
                            cc.pos_key = ContentPosKey::Absolute {
                                depth,
                                offset: o
                            }
                        },
                        _ => {
                            return Err(SuruleParseError::ConflictContentModifier)
                        }
                    }
                } else {
                    return Err(SuruleParseError::WildContentModifier(format!("offset:{:?}", o)))
                }
            },
            SuruleNaivePayloadOption::StartsWith(s) => {
                if let Some(ref mut cc) = current_content {
                    match cc.pos_key {
                        ContentPosKey::NotSet => {
                            cc.pos_key = ContentPosKey::EndsWith(s)
                        },
                        ContentPosKey::StartsWith(_) => {
                            return Err(SuruleParseError::DuplicatedContentModifier("startswith".to_string()))
                        }
                        _ => {
                            return Err(SuruleParseError::ConflictContentModifier)
                        }
                    }
                } else {
                    return Err(SuruleParseError::WildContentModifier(format!("startswith:{:?}", s)))
                }
            },
            SuruleNaivePayloadOption::Within(w) => {
                if let Some(ref mut cc) = current_content {
                    match cc.pos_key {
                        ContentPosKey::NotSet => {
                            cc.pos_key = ContentPosKey::Relative {
                                distance: Default::default(),
                                within: w
                            }
                        },
                        ContentPosKey::Relative { ref distance, ref within } => {
                            if *within != Default::default() {
                                return Err(SuruleParseError::DuplicatedContentModifier("within".to_string()))
                            }
                            cc.pos_key = ContentPosKey::Relative {
                                distance: distance.to_owned(),
                                within: w
                            }
                        },
                        _ => {
                            return Err(SuruleParseError::ConflictContentModifier)
                        }
                    }
                } else {
                    return Err(SuruleParseError::WildContentModifier(format!("within:{:?}", w)))
                }
            },
            /* Other Payload Keywords */
            SuruleNaivePayloadOption::ByteJump(b) => {
                if let Some(cc) = current_content {
                    modified_payload_options.push(SurulePayloadOption::Content(cc));
                    current_content = None;
                }
                modified_payload_options.push(SurulePayloadOption::ByteJump(b))
            },
            SuruleNaivePayloadOption::Dsize(d) => {
                if let Some(cc) = current_content {
                    modified_payload_options.push(SurulePayloadOption::Content(cc));
                    current_content = None;
                }
                modified_payload_options.push(SurulePayloadOption::Dsize(d))
            },
            SuruleNaivePayloadOption::IsDataAt(i) => {
                if let Some(cc) = current_content {
                    modified_payload_options.push(SurulePayloadOption::Content(cc));
                    current_content = None;
                }
                modified_payload_options.push(SurulePayloadOption::IsDataAt(i))
            },
            SuruleNaivePayloadOption::Pcre(p) => {
                if let Some(cc) = current_content {
                    modified_payload_options.push(SurulePayloadOption::Content(cc));
                    current_content = None;
                }
                modified_payload_options.push(SurulePayloadOption::Pcre(p))
            },
            SuruleNaivePayloadOption::RawBytes(_) => {
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