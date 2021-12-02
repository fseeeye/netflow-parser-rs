//! 解析 suricata 规则字符串
//!
//! 解析得到的 Surule 数据结构支持序列化/反序列化，可以简单地撰写程序将该规则转换成 Json / YAML 格式。
mod error;
mod option;
mod parser;
mod surules;
mod utils;

pub mod elements;

pub use error::SuruleParseError;
pub use option::SuruleOption;
pub use surules::VecSurules;

use self::elements::Action;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub enum Surule {
    Tcp(TcpSurule),
    Udp(UdpSurule),
}

impl Surule {
    pub fn new(
        action: Action,
        protocol: elements::Protocol,
        src_addr: elements::IpAddressList,
        src_port: elements::PortList,
        direction: elements::Direction,
        dst_addr: elements::IpAddressList,
        dst_port: elements::PortList,
        options: Vec<SuruleOption>,
    ) -> Self {
        match protocol {
            elements::Protocol::Tcp => Self::Tcp(TcpSurule {
                action,
                src_addr,
                src_port,
                direction,
                dst_addr,
                dst_port,
                options,
            }),
            elements::Protocol::Udp => Self::Udp(UdpSurule {
                action,
                src_addr,
                src_port,
                direction,
                dst_addr,
                dst_port,
                options,
            }),
        }
    }
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct TcpSurule {
    pub action: Action,
    pub src_addr: elements::IpAddressList,
    pub src_port: elements::PortList,
    pub direction: elements::Direction,
    pub dst_addr: elements::IpAddressList,
    pub dst_port: elements::PortList,
    pub options: Vec<SuruleOption>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct UdpSurule {
    pub action: Action,
    pub src_addr: elements::IpAddressList,
    pub src_port: elements::PortList,
    pub direction: elements::Direction,
    pub dst_addr: elements::IpAddressList,
    pub dst_port: elements::PortList,
    pub options: Vec<SuruleOption>,
}
