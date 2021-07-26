use crate::errors::ParseError;

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
    Error(ParseError),
}