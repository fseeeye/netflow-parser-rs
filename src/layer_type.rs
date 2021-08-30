use crate::ParseError;
use serde::{Serialize, Deserialize};

/// LayerType旨在用简单结构来表示协议类型
/// * 协助判断解析出来的packet中各层是什么协议
/// * 也用于options的stop字段说明该在哪一层停止
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum LayerType {
    Link(LinkLayerType),
    Network(NetworkLayerType),
    Transport(TransportLayerType),
    Application(ApplicationLayerType),
    Error(ParseError),
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum LinkLayerType {
    Ethernet,
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum NetworkLayerType {
    Ipv4,
    Ipv6,
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum TransportLayerType {
    Tcp,
    Udp
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum ApplicationLayerType {
    FinsTcpReq,
    FinsTcpRsp,
    FinsUdpReq,
    FinsUdpRsp,
    ModbusReq,
    ModbusRsp,
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash, Serialize, Deserialize)]
pub enum ApplicationLayerNaiveType {
    Fins,
    Modbus,
}