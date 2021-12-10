use anyhow::Result;
use ipnet::Ipv4Net;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use std::fmt::{Display, Formatter};
use std::net::Ipv4Addr;
use std::str::FromStr;

use parsing_parser::{ProtocolType, TransportProtocol};

use crate::surule::utils::is_default;
use crate::surule::SuruleParseError;

pub trait SurList {
    type Element: FromStr<Err = nom::Err<SuruleParseError>>;

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
    RejectBoth,
}

/// Protocol type (Suricata Header Element)
///
/// Warning: 目前暂时只支持：tcp / udp
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Into<ProtocolType> for Protocol {
    fn into(self) -> ProtocolType {
        match self {
            Self::Tcp => ProtocolType::Transport(TransportProtocol::Tcp),
            Self::Udp => ProtocolType::Transport(TransportProtocol::Udp),
        }
    }
}

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
    pub except: Option<Vec<IpAddress>>, // None represent No Exception
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

impl IpAddress {
    pub fn contains(&self, ip: &Ipv4Addr) -> bool {
        match self {
            Self::V4Addr(self_ip) => self_ip == ip,
            &Self::V4Range(self_range) => self_range.contains(ip),
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
    pub except: Option<Vec<Port>>,
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
    Range { max: u16, min: u16 },
    Single(u16),
}

impl Port {
    pub fn new_range(min: u16, max: u16) -> Result<Self, SuruleParseError> {
        if max < min {
            return Err(SuruleParseError::InvalidPort(
                "max port is smaller than min port!".to_string(),
            ));
        }
        Ok(Port::Range { min, max })
    }

    pub fn contains(&self, port: u16) -> bool {
        match self {
            Self::Single(p) => return *p == port,
            Self::Range { max, min } => return *min <= port && port <= *max,
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

    /* Modifiers */
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub nocase: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub fast_pattern: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub pos_key: ContentPosKey,
}

impl Content {
    pub fn new<S: AsRef<str>>(pattern: S) -> Self {
        Self {
            pattern: pattern.as_ref().to_string(),
            ..Default::default() // https://doc.rust-lang.org/std/default/trait.Default.html
        }
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(PartialEq, Debug, Clone)]
pub enum ContentPosKey {
    Absolute { depth: u64, offset: u64 },
    Relative { distance: Distance, within: Within },
    StartsWith(bool),
    EndsWith(bool),
    NotSet,
}

impl Default for ContentPosKey {
    fn default() -> Self {
        return Self::NotSet;
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

/// Flow type (Suricata Body Element)
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Clone)]
pub struct Flow(pub Vec<FlowMatcher>);

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Clone)]
pub enum FlowMatcher {
    #[cfg_attr(feature = "serde", serde(rename = "to_client"))]
    ToClient,
    #[cfg_attr(feature = "serde", serde(rename = "to_server"))]
    ToServer,
    #[cfg_attr(feature = "serde", serde(rename = "from_client"))]
    FromClient,
    #[cfg_attr(feature = "serde", serde(rename = "from_server"))]
    FromServer,
    #[cfg_attr(feature = "serde", serde(rename = "established"))]
    Established,
    #[cfg_attr(feature = "serde", serde(rename = "not_established"))]
    NotEstablished,
    #[cfg_attr(feature = "serde", serde(rename = "stateless"))]
    Stateless,
    #[cfg_attr(feature = "serde", serde(rename = "only_stream"))]
    OnlyStream,
    #[cfg_attr(feature = "serde", serde(rename = "no_stream"))]
    NoStream,
    #[cfg_attr(feature = "serde", serde(rename = "only_frag"))]
    OnlyFrag,
    #[cfg_attr(feature = "serde", serde(rename = "no_frag"))]
    NoFrag,
}

impl FlowMatcher {
    pub fn as_str(&self) -> &str {
        match self {
            Self::ToClient => "to_client",
            Self::ToServer => "to_server",
            Self::FromClient => "from_client",
            Self::FromServer => "from_server",
            Self::Established => "established",
            Self::NotEstablished => "not_established",
            Self::Stateless => "stateless",
            Self::OnlyStream => "only_stream",
            Self::NoStream => "no_stream",
            Self::OnlyFrag => "only_frag",
            Self::NoFrag => "no_frag",
        }
    }
}

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

/// Within modifier type (Suricata Body Element)
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(PartialEq, Default, Debug, Clone)]
pub struct Within(pub CountOrName);

/*
 *  Util Types
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
