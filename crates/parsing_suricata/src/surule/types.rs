//! 包含 suricata rule (Surule) 用到的所有数据结构
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

use std::fmt::{Display, Formatter};
use std::str::FromStr;

use super::utils::is_default;
use super::SuruleParseError;


/*
 *  Suricata Header Element types
 */

/// Direction type (Suricata Header Element)
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub enum Direction {
    #[cfg_attr(feature = "serde", serde(rename = "single"))] // Warning: not "unidirectional" ?
    Single,
    #[cfg_attr(feature = "serde", serde(rename = "both"))] // Warning: not "bidirectional" ?
    Both,
}

impl Default for Direction {
    fn default() -> Self {
        Self::Single
    }
}


/*
 *  Suricata Body (Option) Element types
 */

/// Byte Jump type (Suricata Body Element)
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub struct ByteJump {
    pub count: usize,
    pub offset: i64,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub relative: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub multiplier: usize,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub endian: Endian,

    // These can be bundled into an enum.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub string: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub hex: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub dec: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub oct: bool,

    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub align: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub from_beginning: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub from_end: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub post_offset: i64,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub dce: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub bitmask: u64,
}

// Endian 表示大小端序，用于 Byte Jump 内部
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, PartialEq, Debug)]
#[repr(C)]
pub enum Endian {
    #[cfg_attr(feature = "serde", serde(rename = "big"))]
    Big,
    #[cfg_attr(feature = "serde", serde(rename = "little"))]
    Little,
}

impl Default for Endian {
    fn default() -> Self {
        Self::Big
    }
}

/// Content type (Suricata Body Element)
/// refs: https://suricata.readthedocs.io/en/latest/rules/payload-keywords.html?highlight=content#content
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(PartialEq, Default, Debug, Clone)]
pub struct Content {
    pub pattern: String,

    // Modifiers.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub depth: u64,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub distance: Distance,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub endswith: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub fast_pattern: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub nocase: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub offset: u64,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub startswith: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub within: Within,
}

impl Content {
    pub fn new<S: AsRef<str>>(pattern: S) -> Self {
        Self {
            pattern: pattern.as_ref().to_string(),
            ..Default::default() // https://doc.rust-lang.org/std/default/trait.Default.html
        }
    }
}


/// Distance modifier type (Suricata Body Element)
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(PartialEq, Default, Debug, Clone)]
pub struct Distance(pub CountOrName);


/// FileData type (Suricata Body Element)
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(PartialEq, Default, Debug, Clone)]
pub struct FileData;


/// Flowbits type (Suricata Body Element)
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct Flowbits {
    pub command: FlowbitCommand,
    #[cfg_attr(
        feature = "serde",
        serde(skip_serializing_if = "Vec::is_empty")
    )]
    pub names: Vec<String>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub enum FlowbitCommand {
    #[cfg_attr(feature = "serde", serde(rename = "noalert"))]
    NoAlert,
    #[cfg_attr(feature = "serde", serde(rename = "set"))]
    Set,
    #[cfg_attr(feature = "serde", serde(rename = "isset"))]
    IsSet,
    #[cfg_attr(feature = "serde", serde(rename = "toggle"))]
    Toggle,
    #[cfg_attr(feature = "serde", serde(rename = "unset"))]
    Unset,
    #[cfg_attr(feature = "serde", serde(rename = "isnotset"))]
    IsNotSet,
}

impl Display for FlowbitCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::IsNotSet => "isnotset",
            Self::IsSet => "isset",
            Self::Toggle => "toggle",
            Self::Unset => "unset",
            Self::NoAlert => "noalert",
            Self::Set => "set",
        };
        write!(f, "{}", label)
    }
}

impl FromStr for FlowbitCommand {
    // Use nom::Err to satisfy ? in parser.
    type Err = nom::Err<SuruleParseError<&'static str>>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "noalert" => Ok(Self::NoAlert),
            "set" => Ok(Self::Set),
            "isset" => Ok(Self::IsSet),
            "toggle" => Ok(Self::Toggle),
            "unset" => Ok(Self::Unset),
            "isnotset" => Ok(Self::IsNotSet),
            _ => Err(nom::Err::Error(SuruleParseError::Flowbit(format!(
                "unknown command: {}",
                s
            )))),
        }
    }
}


/// Within modifier type (Suricata Body Element)
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(PartialEq, Default, Debug, Clone)]
pub struct Within(pub CountOrName);


/*
 *  Extra Types
 */

/// CountOrName type 
/// 
/// 用于扩展 suricate body 的可选字段，使其的值可以是 i64 或者 String 
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub enum CountOrName {
    #[cfg_attr(feature = "serde", serde(rename = "value"))]
    Value(i64),
    #[cfg_attr(feature = "serde", serde(rename = "varname"))]
    Var(String),
}

impl Default for CountOrName {
    fn default() -> Self {
        Self::Value(0)
    }
}

/// Generic option type
/// 
/// A generic option, used for unknown rule options.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct GenericOption {
    pub name: String,
    pub val: Option<String>,
}