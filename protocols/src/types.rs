#[derive(Debug, PartialEq)]
pub enum LayerType {
    Eof,
    Ethernet,
    Ipv4,
    Ipv6,
    ModbusReq,
    ModbusRsp,
    Tcp,
    Udp,
    None
}