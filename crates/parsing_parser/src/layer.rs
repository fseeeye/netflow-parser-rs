use crate::parsers::*;
use crate::protocol::{ApplicationProtocol, LinkProtocol, NetworkProtocol, TransportProtocol};
/// Layer是包含协议解析结果的数据结构
use crate::ProtocolType;

/// LinkLayer是表示link层内容的类型。
#[derive(Debug, PartialEq, Clone)]
pub enum LinkLayer {
    Ethernet(EthernetHeader),
}

// 层 -> 协议类型
impl Into<ProtocolType> for LinkLayer {
    fn into(self) -> ProtocolType {
        match self {
            LinkLayer::Ethernet(_) => ProtocolType::Link(LinkProtocol::Ethernet),
        }
    }
}

/// NetworkLayer是表示network层内容的类型。
#[derive(Debug, PartialEq, Clone)]
pub enum NetworkLayer<'a> {
    Ipv4(Ipv4Header<'a>),
    Ipv6(Ipv6Header<'a>),
}

impl<'a> Into<ProtocolType> for NetworkLayer<'a> {
    fn into(self) -> ProtocolType {
        match self {
            NetworkLayer::Ipv4(_) => ProtocolType::Network(NetworkProtocol::Ipv4),
            NetworkLayer::Ipv6(_) => ProtocolType::Network(NetworkProtocol::Ipv6),
        }
    }
}

/// TransportLayer是表示transport层内容的类型。
#[derive(Debug, PartialEq, Clone)]
pub enum TransportLayer<'a> {
    Tcp(TcpHeader<'a>),
    Udp(UdpHeader),
}

impl<'a> Into<ProtocolType> for TransportLayer<'a> {
    fn into(self) -> ProtocolType {
        match self {
            TransportLayer::Tcp(_) => ProtocolType::Transport(TransportProtocol::Tcp),
            TransportLayer::Udp(_) => ProtocolType::Transport(TransportProtocol::Udp),
        }
    }
}

/// ApplicationLayer是表示application层内容的类型。
#[derive(Debug, PartialEq, Clone)]
pub enum ApplicationLayer<'a> {
    ModbusReq(ModbusReqHeader<'a>),
    ModbusRsp(ModbusRspHeader<'a>),
    FinsTcpReq(FinsTcpReqHeader<'a>),
    FinsTcpRsp(FinsTcpRspHeader<'a>),
    FinsUdpReq(FinsUdpReqHeader<'a>),
    FinsUdpRsp(FinsUdpRspHeader<'a>),
    Mms(MmsHeader<'a>),
    S7comm(S7commHeader<'a>),
    Bacnet(BacnetHeader<'a>),
    Dnp3(Dnp3Header<'a>),
    Iec104(Iec104Header),
    Opcua(OpcuaHeader<'a>),
    IsoOnTcp(IsoOnTcpHeader),
}

impl<'a> Into<ProtocolType> for ApplicationLayer<'a> {
    fn into(self) -> ProtocolType {
        match self {
            ApplicationLayer::ModbusReq(_) => {
                ProtocolType::Application(ApplicationProtocol::ModbusReq)
            }
            ApplicationLayer::ModbusRsp(_) => {
                ProtocolType::Application(ApplicationProtocol::ModbusRsp)
            }
            ApplicationLayer::FinsTcpReq(_) => {
                ProtocolType::Application(ApplicationProtocol::FinsTcpReq)
            }
            ApplicationLayer::FinsTcpRsp(_) => {
                ProtocolType::Application(ApplicationProtocol::FinsTcpRsp)
            }
            ApplicationLayer::FinsUdpReq(_) => {
                ProtocolType::Application(ApplicationProtocol::FinsUdpReq)
            }
            ApplicationLayer::FinsUdpRsp(_) => {
                ProtocolType::Application(ApplicationProtocol::FinsUdpRsp)
            }
            ApplicationLayer::Mms(_) => ProtocolType::Application(ApplicationProtocol::Mms),
            ApplicationLayer::S7comm(_) => ProtocolType::Application(ApplicationProtocol::S7comm),
            ApplicationLayer::Bacnet(_) => ProtocolType::Application(ApplicationProtocol::Bacnet),
            ApplicationLayer::Dnp3(_) => ProtocolType::Application(ApplicationProtocol::Dnp3),
            ApplicationLayer::Iec104(_) => ProtocolType::Application(ApplicationProtocol::Iec104),
            ApplicationLayer::Opcua(_) => ProtocolType::Application(ApplicationProtocol::Opcua),
            ApplicationLayer::IsoOnTcp(_) => {
                ProtocolType::Application(ApplicationProtocol::IsoOnTcp)
            }
        }
    }
}
