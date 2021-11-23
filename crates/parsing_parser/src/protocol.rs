use crate::ParseError;
use serde::{Serialize, Deserialize};

/// ProtocolType旨在用简单结构来表示协议类型
/// * 协助判断解析出来的packet中各层是什么协议
/// * 也用于options的stop字段说明该在哪一层停止
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum ProtocolType {
    Link(LinkProtocol),
    Network(NetworkProtocol),
    Transport(TransportProtocol),
    Application(ApplicationProtocol),
    Error(ParseError),
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum LinkProtocol {
    Ethernet,
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum NetworkProtocol {
    Ipv4,
    Ipv6,
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

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

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash, Serialize, Deserialize)]
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
