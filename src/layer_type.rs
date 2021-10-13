use crate::ParseError;
use serde::{Serialize, Deserialize};

/// LayerType旨在用简单结构来表示协议类型
/// * 协助判断解析出来的packet中各层是什么协议
/// * 也用于options的stop字段说明该在哪一层停止
#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum LayerType {
    Link(LinkLayerType),
    Network(NetworkLayerType),
    Transport(TransportLayerType),
    Application(ApplicationLayerType),
    Error(ParseError),
}

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum LinkLayerType {
    Ethernet,
}

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum NetworkLayerType {
    Ipv4,
    Ipv6,
}

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum TransportLayerType {
    Tcp,
    Udp,
}

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum ApplicationLayerType {
    ModbusReq,
    ModbusRsp,
    FinsTcpReq,
    FinsTcpRsp,
    FinsUdpReq,
    FinsUdpRsp,
    Mms,
    S7comm,
    Bacnet,
    IsoOnTcp,
}

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash, Serialize, Deserialize)]
pub enum ApplicationLayerNaiveType {
    Modbus,
    Fins,
    Mms,
    S7comm,
    Bacnet,
    IsoOnTcp,
}
