use crate::ParseError;

/// LayerType旨在用简单结构来表示协议类型
/// * 协助判断解析出来的packet中各层是什么协议
/// * 也用于options的stop字段说明该在哪一层停止
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum LayerType {
    Eof,
    Ethernet,
    Ipv4,
    Ipv6,
    ModbusReq,
    ModbusRsp,
    Tcp,
    Udp,
    Error(ParseError)
}