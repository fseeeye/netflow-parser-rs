use crate::ParseError;
use serde::{Deserialize, Serialize};

/// ProtocolType旨在用简单结构来表示协议类型
/// * 协助判断解析出来的packet中各层是什么协议
/// * 也用于options的stop字段说明该在哪一层停止
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Hash)]
pub enum ProtocolType {
    Link(LinkProtocol),
    Network(NetworkProtocol),
    Transport(TransportProtocol),
    Application(ApplicationProtocol),
    Error(ParseError),
}

impl PartialEq for ProtocolType {
    fn eq(&self, other: &Self) -> bool {
        match self {
            Self::Link(p) => match other {
                Self::Link(op) => return *p == *op,
                _ => return false,
            },
            Self::Network(p) => match other {
                Self::Network(op) => return *p == *op,
                _ => return false,
            },
            Self::Transport(p) => match other {
                Self::Transport(op) => return *p == *op,
                _ => return false,
            },
            Self::Application(p) => match other {
                Self::Application(op) => {
                    let p: ApplicationNaiveProtocol = p.into();
                    let op = op.into();
                    return p == op;
                }
                _ => return false,
            },
            Self::Error(_) => return false,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum LinkProtocol {
    Ethernet,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum NetworkProtocol {
    Ipv4,
    Ipv6,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum ApplicationProtocol {
    ModbusReq,
    ModbusRsp,
    FinsTcpReq,
    FinsTcpRsp,
    FinsUdpReq,
    FinsUdpRsp,
    Mms,
    S7comm,
    Bacnet,
    Dnp3,
    Iec104,
    Opcua,
    IsoOnTcp,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum ApplicationNaiveProtocol {
    Modbus,
    Fins,
    Mms,
    S7comm,
    Bacnet,
    Dnp3,
    Iec104,
    Opcua,
    IsoOnTcp,
}

impl From<ApplicationProtocol> for ApplicationNaiveProtocol {
    fn from(p: ApplicationProtocol) -> Self {
        match p {
            ApplicationProtocol::Bacnet => ApplicationNaiveProtocol::Bacnet,
            ApplicationProtocol::Dnp3 => ApplicationNaiveProtocol::Dnp3,
            ApplicationProtocol::FinsTcpReq => ApplicationNaiveProtocol::Fins,
            ApplicationProtocol::FinsTcpRsp => ApplicationNaiveProtocol::Fins,
            ApplicationProtocol::FinsUdpReq => ApplicationNaiveProtocol::Fins,
            ApplicationProtocol::FinsUdpRsp => ApplicationNaiveProtocol::Fins,
            ApplicationProtocol::Iec104 => ApplicationNaiveProtocol::Iec104,
            ApplicationProtocol::IsoOnTcp => ApplicationNaiveProtocol::IsoOnTcp,
            ApplicationProtocol::Mms => ApplicationNaiveProtocol::Mms,
            ApplicationProtocol::ModbusReq => ApplicationNaiveProtocol::Modbus,
            ApplicationProtocol::ModbusRsp => ApplicationNaiveProtocol::Modbus,
            ApplicationProtocol::Opcua => ApplicationNaiveProtocol::Opcua,
            ApplicationProtocol::S7comm => ApplicationNaiveProtocol::S7comm,
        }
    }
}

impl From<&ApplicationProtocol> for ApplicationNaiveProtocol {
    fn from(p: &ApplicationProtocol) -> Self {
        match p {
            ApplicationProtocol::Bacnet => ApplicationNaiveProtocol::Bacnet,
            ApplicationProtocol::Dnp3 => ApplicationNaiveProtocol::Dnp3,
            ApplicationProtocol::FinsTcpReq => ApplicationNaiveProtocol::Fins,
            ApplicationProtocol::FinsTcpRsp => ApplicationNaiveProtocol::Fins,
            ApplicationProtocol::FinsUdpReq => ApplicationNaiveProtocol::Fins,
            ApplicationProtocol::FinsUdpRsp => ApplicationNaiveProtocol::Fins,
            ApplicationProtocol::Iec104 => ApplicationNaiveProtocol::Iec104,
            ApplicationProtocol::IsoOnTcp => ApplicationNaiveProtocol::IsoOnTcp,
            ApplicationProtocol::Mms => ApplicationNaiveProtocol::Mms,
            ApplicationProtocol::ModbusReq => ApplicationNaiveProtocol::Modbus,
            ApplicationProtocol::ModbusRsp => ApplicationNaiveProtocol::Modbus,
            ApplicationProtocol::Opcua => ApplicationNaiveProtocol::Opcua,
            ApplicationProtocol::S7comm => ApplicationNaiveProtocol::S7comm,
        }
    }
}
