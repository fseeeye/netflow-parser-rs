use crate::{LayerType, layer_type::{ApplicationLayerType, LinkLayerType, NetworkLayerType, TransportLayerType}, parsers::*};

/// LinkLayer是表示link层各类协议信息的类型。
#[derive(Debug, PartialEq, Clone)]
pub enum LinkLayer {
    Ethernet(EthernetHeader),
}

impl Into<LayerType> for LinkLayer {
    fn into(self) -> LayerType {
        match self {
            LinkLayer::Ethernet(_) => LayerType::Link(LinkLayerType::Ethernet),
        }
    }
}

/// NetworkLayer是表示network层各类协议信息的类型。
#[derive(Debug, PartialEq, Clone)]
pub enum NetworkLayer<'a> {
    Ipv4(Ipv4Header<'a>),
    Ipv6(Ipv6Header<'a>),
}

impl<'a> Into<LayerType> for NetworkLayer<'a> {
    fn into(self) -> LayerType {
        match self {
            NetworkLayer::Ipv4(_) => LayerType::Network(NetworkLayerType::Ipv4),
            NetworkLayer::Ipv6(_) => LayerType::Network(NetworkLayerType::Ipv6),
        }
    }
}

/// TransportLayer是表示transport层各类协议新的类型。
#[derive(Debug, PartialEq, Clone)]
pub enum TransportLayer<'a> {
    Tcp(TcpHeader<'a>),
    Udp(UdpHeader),
}

impl<'a> Into<LayerType> for TransportLayer<'a> {
    fn into(self) -> LayerType {
        match self {
            TransportLayer::Tcp(_) => LayerType::Transport(TransportLayerType::Tcp),
            TransportLayer::Udp(_) => LayerType::Transport(TransportLayerType::Udp),
        }
    }
}

/// ApplicationLayer是表示application层各类协议新的类型。
#[derive(Debug, PartialEq, Clone)]
pub enum ApplicationLayer<'a> {
    ModbusReq(ModbusReqHeader<'a>),
    ModbusRsp(ModbusRspHeader<'a>),
    FinsTcpReq(FinsTcpReqHeader<'a>),
    FinsTcpRsp(FinsTcpRspHeader<'a>),
    FinsUdpReq(FinsUdpReqHeader<'a>),
    FinsUdpRsp(FinsUdpRspHeader<'a>),
}

impl<'a> Into<LayerType> for ApplicationLayer<'a> {
    fn into(self) -> LayerType {
        match self {
            ApplicationLayer::FinsTcpReq(_) => LayerType::Application(ApplicationLayerType::FinsTcpReq),
            ApplicationLayer::FinsTcpRsp(_) => LayerType::Application(ApplicationLayerType::FinsTcpRsp),
            ApplicationLayer::FinsUdpReq(_) => LayerType::Application(ApplicationLayerType::FinsUdpReq),
            ApplicationLayer::FinsUdpRsp(_) => LayerType::Application(ApplicationLayerType::FinsUdpRsp),
            ApplicationLayer::ModbusReq(_) => LayerType::Application(ApplicationLayerType::ModbusReq),
            ApplicationLayer::ModbusRsp(_) => LayerType::Application(ApplicationLayerType::ModbusRsp),
        }
    }
}