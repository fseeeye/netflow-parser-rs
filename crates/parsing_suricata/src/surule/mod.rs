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
pub use surules::{Surules, VecSurules};

use self::{
    elements::Action,
    option::{
        SuruleFlowOption, SuruleMetaOption, SurulePayloadOption, SuruleTcpOption, SuruleUdpOption,
    },
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub enum Surule {
    Tcp(TcpSurule),
    Udp(UdpSurule),
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct TcpSurule {
    // required
    pub action: Action,
    pub src_addr: elements::IpAddressList,
    pub src_port: elements::PortList,
    pub direction: elements::Direction,
    pub dst_addr: elements::IpAddressList,
    pub dst_port: elements::PortList,
    // optional
    pub meta_options: Vec<SuruleMetaOption>,
    pub payload_options: Vec<SurulePayloadOption>,
    pub flow_options: Vec<SuruleFlowOption>,
    pub tcp_options: Vec<SuruleTcpOption>,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct UdpSurule {
    // required
    pub action: Action,
    pub src_addr: elements::IpAddressList,
    pub src_port: elements::PortList,
    pub direction: elements::Direction,
    pub dst_addr: elements::IpAddressList,
    pub dst_port: elements::PortList,
    // optional
    pub meta_options: Vec<SuruleMetaOption>,
    pub payload_options: Vec<SurulePayloadOption>,
    pub flow_options: Vec<SuruleFlowOption>,
    pub udp_options: Vec<SuruleUdpOption>,
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
            elements::Protocol::Tcp => Self::Tcp(TcpSurule::new(
                action, src_addr, src_port, direction, dst_addr, dst_port, options,
            )),
            elements::Protocol::Udp => Self::Udp(UdpSurule::new(
                action, src_addr, src_port, direction, dst_addr, dst_port, options,
            )),
        }
    }
}

pub trait InnerSurule {
    fn new(
        action: Action,
        src_addr: elements::IpAddressList,
        src_port: elements::PortList,
        direction: elements::Direction,
        dst_addr: elements::IpAddressList,
        dst_port: elements::PortList,
        options: Vec<SuruleOption>,
    ) -> Self;
}

impl InnerSurule for TcpSurule {
    fn new(
        action: Action,
        src_addr: elements::IpAddressList,
        src_port: elements::PortList,
        direction: elements::Direction,
        dst_addr: elements::IpAddressList,
        dst_port: elements::PortList,
        options: Vec<SuruleOption>,
    ) -> Self {
        let mut meta_options = Vec::new();
        let mut payload_options = Vec::new();
        let mut flow_options = Vec::new();
        let mut tcp_options = Vec::new();

        for option in options {
            match option {
                SuruleOption::Meta(o) => meta_options.push(o),
                SuruleOption::Payload(o) => payload_options.push(o),
                SuruleOption::Flow(o) => flow_options.push(o),
                SuruleOption::TCP(o) => tcp_options.push(o),
                _ => {}
            }
        }

        Self {
            action,
            src_addr,
            src_port,
            direction,
            dst_addr,
            dst_port,
            meta_options,
            payload_options,
            flow_options,
            tcp_options,
        }
    }
}

impl InnerSurule for UdpSurule {
    fn new(
        action: Action,
        src_addr: elements::IpAddressList,
        src_port: elements::PortList,
        direction: elements::Direction,
        dst_addr: elements::IpAddressList,
        dst_port: elements::PortList,
        options: Vec<SuruleOption>,
    ) -> Self {
        let mut meta_options = Vec::new();
        let mut payload_options = Vec::new();
        let mut flow_options = Vec::new();
        let mut udp_options = Vec::new();

        for option in options {
            match option {
                SuruleOption::Meta(o) => meta_options.push(o),
                SuruleOption::Payload(o) => payload_options.push(o),
                SuruleOption::Flow(o) => flow_options.push(o),
                SuruleOption::UDP(o) => udp_options.push(o),
                _ => {}
            }
        }

        Self {
            action,
            src_addr,
            src_port,
            direction,
            dst_addr,
            dst_port,
            meta_options,
            payload_options,
            flow_options,
            udp_options,
        }
    }
}
