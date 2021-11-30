use crate::ParseError;
use serde::{Serialize, Deserialize};

/// ProtocolType旨在用简单结构来表示协议类型
/// * 协助判断解析出来的packet中各层是什么协议
/// * 也用于options的stop字段说明该在哪一层停止
#[derive(Serialize, Deserialize)]
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum ProtocolType {
    Link(LinkProtocol),
    Network(NetworkProtocol),
    Transport(TransportProtocol),
    Application(ApplicationProtocol),
    Error(ParseError),
}

#[derive(Serialize, Deserialize)]
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum LinkProtocol {
    Ethernet,
}

#[derive(Serialize, Deserialize)]
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum NetworkProtocol {
    Ipv4,
    Ipv6,
}

#[derive(Serialize, Deserialize)]
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Serialize, Deserialize)]
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
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

#[derive(Serialize, Deserialize)]
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
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
            ApplicationProtocol::Bacnet     => ApplicationNaiveProtocol::Bacnet,
            ApplicationProtocol::Dnp3       => ApplicationNaiveProtocol::Dnp3,
            ApplicationProtocol::FinsTcpReq => ApplicationNaiveProtocol::Fins,
            ApplicationProtocol::FinsTcpRsp => ApplicationNaiveProtocol::Fins,
            ApplicationProtocol::FinsUdpReq => ApplicationNaiveProtocol::Fins,
            ApplicationProtocol::FinsUdpRsp => ApplicationNaiveProtocol::Fins,
            ApplicationProtocol::Iec104     => ApplicationNaiveProtocol::Iec104,
            ApplicationProtocol::IsoOnTcp   => ApplicationNaiveProtocol::IsoOnTcp,
            ApplicationProtocol::Mms        => ApplicationNaiveProtocol::Mms,
            ApplicationProtocol::ModbusReq  => ApplicationNaiveProtocol::Modbus,
            ApplicationProtocol::ModbusRsp  => ApplicationNaiveProtocol::Modbus,
            ApplicationProtocol::Opcua      => ApplicationNaiveProtocol::Opcua,
            ApplicationProtocol::S7comm     => ApplicationNaiveProtocol::S7comm,
        }
    }
}