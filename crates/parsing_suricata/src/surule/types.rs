//! 包含 suricata rule (Surule) 用到的所有数据结构
use ipnet::Ipv4Net;
use anyhow::{Result};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use std::fmt::{Display, Formatter};
use std::net::Ipv4Addr;
use std::str::FromStr;

use parsing_parser::ProtocolType;

use super::element_parser::handle_value;
use super::utils::is_default;
use super::SuruleParseError;
use super::types;


pub trait SurList {
    type Element: FromStr<Err = nom::Err<SuruleParseError<&'static str>>>;

    fn get_accept(&self) -> &Option<Vec<Self::Element>>;
    fn get_expect(&self) -> &Option<Vec<Self::Element>>;
    fn get_accept_mut(&mut self) -> &mut Option<Vec<Self::Element>>;
    fn get_expect_mut(&mut self) -> &mut Option<Vec<Self::Element>>;
}

/*
 *  Suricata Header Element types
 */

/// Action type (Suricata Header Element)
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    #[cfg_attr(feature = "serde", serde(rename = "alert"))]
    Alert,
    #[cfg_attr(feature = "serde", serde(rename = "pass"))]
    Pass,
    #[cfg_attr(feature = "serde", serde(rename = "drop"))]
    Drop,
    #[cfg_attr(feature = "serde", serde(rename = "reject"))]
    Reject,
    #[cfg_attr(feature = "serde", serde(rename = "rejectsrc"))]
    RejectSrc,
    #[cfg_attr(feature = "serde", serde(rename = "rejectdst"))]
    RejectDst,
    #[cfg_attr(feature = "serde", serde(rename = "rejectboth"))]
    RejectBoth
}

/// Protocol type (Suricata Header Element)
/// 
/// use parsing_parser::protocol::ProtocolType
pub type Protocol = ProtocolType;

/// IP List type (Suricata Header Element: src_addr & dst_addr)
/// 
/// 目前暂不支持：
///     * yaml settings
/// 目前支持不完善：
///     * ip range
///     * 暂时用 vec 存储 ip 规则，检测时遍历比较。
///  ref: https://suricata.readthedocs.io/en/latest/rules/intro.html#source-and-destination
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Default)]
pub struct IpAddressList {
    pub accept: Option<Vec<IpAddress>>, // None represent Any
    pub except: Option<Vec<IpAddress>>  // None represent No Exception
}

impl SurList for IpAddressList {
    type Element = IpAddress;

    fn get_accept(&self) -> &Option<Vec<Self::Element>> {
        &self.accept
    }

    fn get_expect(&self) -> &Option<Vec<Self::Element>> {
        &self.except
    }

    fn get_accept_mut(&mut self) -> &mut Option<Vec<Self::Element>> {
        &mut self.accept
    }

    fn get_expect_mut(&mut self) -> &mut Option<Vec<Self::Element>> {
        &mut self.except
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub enum IpAddress {
    V4Addr(Ipv4Addr),
    V4Range(Ipv4Net), // 简易 ip range 方案
}

impl FromStr for IpAddress {
    type Err = nom::Err<SuruleParseError<&'static str>>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let make_err = |reason| SuruleParseError::InvalidIpAddr(reason).into();

        let ip_addr_str = handle_value(s)
            .map_err(|_| make_err("empty value.".to_string()))?;

        match ip_addr_str.parse::<Ipv4Addr>() {
            Ok(single_addr) => Ok(types::IpAddress::V4Addr(single_addr)),
            Err(_) => { // maybe it's a range
                let single_range = ip_addr_str
                    .parse::<Ipv4Net>()
                    .map_err(|_| make_err(ip_addr_str.to_string()))?;
                Ok(types::IpAddress::V4Range(single_range))
            }
        }
    }
}

/// Port List type (Suricata Header Element)
/// 
///  ref: https://suricata.readthedocs.io/en/latest/rules/intro.html#ports-source-and-destination
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Default)]
pub struct PortList {
    pub accept: Option<Vec<Port>>,
    pub except: Option<Vec<Port>>
}

impl SurList for PortList {
    type Element = Port;

    fn get_accept(&self) -> &Option<Vec<Self::Element>> {
        &self.accept
    }

    fn get_expect(&self) -> &Option<Vec<Self::Element>> {
        &self.except
    }

    fn get_accept_mut(&mut self) -> &mut Option<Vec<Self::Element>> {
        &mut self.accept
    }

    fn get_expect_mut(&mut self) -> &mut Option<Vec<Self::Element>> {
        &mut self.except
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub enum Port {
    Range {max: u16, min: u16},
    Single(u16)
}

impl Port {
    pub fn new_range(min: u16, max: u16) -> Result<Self, SuruleParseError<&'static str>> {
        if max < min {
            return Err(SuruleParseError::InvalidPort("max port is smaller than min port!".to_string()));
        } 
        Ok(Port::Range { min, max })
    }

    pub fn contains(&self, port: u16) -> bool {
        match self {
            Self::Single(p) => return *p == port,
            Self::Range{ max, min} => return *min <= port && port <= *max
        }
    }
}

impl FromStr for Port {
    type Err = nom::Err<SuruleParseError<&'static str>>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let make_err = || SuruleParseError::InvalidPort(s.to_string()).into();

        if let Some((min_str, max_str)) = s.split_once(':') { // range
            let min = min_str
                .parse()
                .map_err(|_| make_err())?;
            let max = max_str.trim()
                .parse()
                .or_else(|e| {
                    if max_str.trim().is_empty() {
                        return Ok(u16::MAX)
                    } else {
                        return Err(e)
                    }
                })
                .map_err(|_| make_err())?;
            Ok(Self::new_range(min, max).map_err(|e| e.into())?)
        } else { // single
            Ok(Self::Single(s.parse().map_err(|_| make_err())?))
        }
    }
}

/// Direction type (Suricata Header Element)
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub enum Direction {
    #[cfg_attr(feature = "serde", serde(rename = "uni"))]
    Uni,
    #[cfg_attr(feature = "serde", serde(rename = "bi"))]
    Bi,
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
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Vec::is_empty"))]
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
