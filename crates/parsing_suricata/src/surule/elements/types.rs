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
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    Alert,
    Pass,
    Drop,
    Reject,
    RejectSrc,
    RejectDst,
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
    pub count: u8,
    pub offset: isize,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub relative: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub multiplier: Option<usize>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub endian: Option<Endian>,

    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub string: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub num_type: Option<NumType>,

    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub align: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub from: Option<ByteJumpFrom>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub post_offset: Option<isize>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub dce: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub bitmask: Option<usize>,
}

// 表示 converted bytes 以字符串解析时的数字类型
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, PartialEq, Debug)]
#[repr(C)]
pub enum NumType {
    #[cfg_attr(feature = "serde", serde(rename = "hex"))]
    HEX,
    #[cfg_attr(feature = "serde", serde(rename = "dec"))]
    DEC,
    #[cfg_attr(feature = "serde", serde(rename = "oct"))]
    OCT,
}

impl Default for NumType {
    fn default() -> Self {
        Self::DEC
    }
}

// 表示 jump 起始位置
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, PartialEq, Debug)]
#[repr(C)]
pub enum ByteJumpFrom {
    #[cfg_attr(feature = "serde", serde(rename = "hex"))]
    BEGIN,
    #[cfg_attr(feature = "serde", serde(rename = "dec"))]
    END,
}

// 表示大小端序
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

/// Byte Test type (Suricata Body Element)
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, Default, PartialEq)]
#[repr(C)]
pub struct ByteTest {
    pub count: u8,
    pub op_nagation: bool,
    pub operator: ByteTestOp,
    pub test_value: u64,
    pub offset: isize,

    pub relative: bool,
    pub endian: Option<Endian>,
    pub string: bool,
    pub num_type: Option<NumType>,
    pub dce: bool,
    pub bitmask: Option<u64>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
#[repr(C)]
pub enum ByteTestOp {
    Less,
    Greater,
    Equal,
    LessEqual,
    GreaterEquanl,
    And,
    Or,
}

impl Default for ByteTestOp {
    fn default() -> Self {
        ByteTestOp::Less
    }
}

/// Dsize Type (Suricata Body Element)
/// refs: https://suricata.readthedocs.io/en/latest/rules/payload-keywords.html#dsize
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
#[repr(C)]
pub enum Dsize {
    Equal(usize),
    NotEqual(usize),
    Less(usize),
    Greater(usize),
    Range(usize, usize),
}

/// IsDataAt Type (Suricata Body Element)
/// refs: https://suricata.readthedocs.io/en/latest/rules/payload-keywords.html#isdataat
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Default)]
#[repr(C)]
pub struct IsDataAt {
    pub pos: usize,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub negate: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub relative: bool,
}

/// Pcre Type (Suricata Body Element)
/// refs: https://suricata.readthedocs.io/en/latest/rules/payload-keywords.html#pcre-perl-compatible-regular-expressions
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, PartialEq, Debug, Default)]
#[repr(C)]
pub struct Pcre {
    pub pattern: String,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub negate: bool,
    // Warning: only support patical modifiers
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub modifier_i: bool, // caseless
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub modifier_m: bool, // multi line
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub modifier_s: bool, // dotall
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub modifier_x: bool, // extended
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub modifier_u: bool, // utf-8
}

/// Content type (Suricata Body Element)
/// refs: https://suricata.readthedocs.io/en/latest/rules/payload-keywords.html?highlight=content#content
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(PartialEq, Default, Debug, Clone)]
pub struct Content {
    pub pattern: Vec<u8>,

    /* Modifiers */
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub nocase: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub fast_pattern: bool,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "is_default"))]
    pub pos_key: ContentPosKey,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(PartialEq, Debug, Clone)]
pub enum ContentPosKey {
    Absolute {
        depth: Option<usize>,
        offset: Option<usize>,
    },
    Relative {
        within: Option<usize>,
        distance: Option<isize>,
    },
    StartsWith,
    EndsWith,
    NotSet,
}

impl Default for ContentPosKey {
    fn default() -> Self {
        return Self::NotSet;
    }
}

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
    #[allow(dead_code)]
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

/// Xbits Type
pub type XbitCommand = FlowbitCommand;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
#[repr(C)]
pub struct XBits {
    pub command: XbitCommand,
    pub name: String,
    pub track: String,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub expire: Option<u64>,
}

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
