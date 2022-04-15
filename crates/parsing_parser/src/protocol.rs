use crate::{ApplicationLayer, LinkLayer, NetworkLayer, ParseError, TransportLayer};
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

impl ToString for LinkProtocol {
    fn to_string(&self) -> String {
        match self {
            LinkProtocol::Ethernet => "Ethernet"
        }.into()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum NetworkProtocol {
    Ipv4,
    Ipv6,
    Goose,
    Vlan,
}

impl ToString for NetworkProtocol {
    fn to_string(&self) -> String {
        match self {
            NetworkProtocol::Ipv4  => "Ipv4",
            NetworkProtocol::Ipv6  => "Ipv6",
            NetworkProtocol::Goose => "Goose",
            NetworkProtocol::Vlan  => "VLan",
        }.into()
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Sv,
}

impl ToString for TransportProtocol {
    fn to_string(&self) -> String {
        match self {
            TransportProtocol::Tcp => "TCP",
            TransportProtocol::Udp => "UDP",
            TransportProtocol::Sv  => "SV"
        }.into()
    }
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
    Http,
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
    Http,
    IsoOnTcp,
}

impl ToString for ApplicationNaiveProtocol {
    fn to_string(&self) -> String {
        match self {
            ApplicationNaiveProtocol::Bacnet   => "BACnet",
            ApplicationNaiveProtocol::Dnp3     => "DNP3",
            ApplicationNaiveProtocol::Fins     => "FINS",
            ApplicationNaiveProtocol::Http     => "HTTP",
            ApplicationNaiveProtocol::Iec104   => "IEC104",
            ApplicationNaiveProtocol::IsoOnTcp => "ISOonTCP",
            ApplicationNaiveProtocol::Mms      => "MMS",
            ApplicationNaiveProtocol::Modbus   => "Modbus",
            ApplicationNaiveProtocol::Opcua    => "OpcUA",
            ApplicationNaiveProtocol::S7comm   => "S7COMM"
        }.into()
    }
}

impl From<ApplicationProtocol> for ApplicationNaiveProtocol {
    fn from(p: ApplicationProtocol) -> Self {
        match p {
            ApplicationProtocol::ModbusReq => ApplicationNaiveProtocol::Modbus,
            ApplicationProtocol::ModbusRsp => ApplicationNaiveProtocol::Modbus,
            ApplicationProtocol::FinsTcpReq => ApplicationNaiveProtocol::Fins,
            ApplicationProtocol::FinsTcpRsp => ApplicationNaiveProtocol::Fins,
            ApplicationProtocol::FinsUdpReq => ApplicationNaiveProtocol::Fins,
            ApplicationProtocol::FinsUdpRsp => ApplicationNaiveProtocol::Fins,
            ApplicationProtocol::Mms => ApplicationNaiveProtocol::Mms,
            ApplicationProtocol::S7comm => ApplicationNaiveProtocol::S7comm,
            ApplicationProtocol::Bacnet => ApplicationNaiveProtocol::Bacnet,
            ApplicationProtocol::Dnp3 => ApplicationNaiveProtocol::Dnp3,
            ApplicationProtocol::Iec104 => ApplicationNaiveProtocol::Iec104,
            ApplicationProtocol::Opcua => ApplicationNaiveProtocol::Opcua,
            ApplicationProtocol::Http => ApplicationNaiveProtocol::Http,
            ApplicationProtocol::IsoOnTcp => ApplicationNaiveProtocol::IsoOnTcp,
        }
    }
}

impl From<&ApplicationProtocol> for ApplicationNaiveProtocol {
    fn from(p: &ApplicationProtocol) -> Self {
        match p {
            ApplicationProtocol::ModbusReq => ApplicationNaiveProtocol::Modbus,
            ApplicationProtocol::ModbusRsp => ApplicationNaiveProtocol::Modbus,
            ApplicationProtocol::FinsTcpReq => ApplicationNaiveProtocol::Fins,
            ApplicationProtocol::FinsTcpRsp => ApplicationNaiveProtocol::Fins,
            ApplicationProtocol::FinsUdpReq => ApplicationNaiveProtocol::Fins,
            ApplicationProtocol::FinsUdpRsp => ApplicationNaiveProtocol::Fins,
            ApplicationProtocol::Mms => ApplicationNaiveProtocol::Mms,
            ApplicationProtocol::S7comm => ApplicationNaiveProtocol::S7comm,
            ApplicationProtocol::Bacnet => ApplicationNaiveProtocol::Bacnet,
            ApplicationProtocol::Dnp3 => ApplicationNaiveProtocol::Dnp3,
            ApplicationProtocol::Iec104 => ApplicationNaiveProtocol::Iec104,
            ApplicationProtocol::Opcua => ApplicationNaiveProtocol::Opcua,
            ApplicationProtocol::Http => ApplicationNaiveProtocol::Http,
            ApplicationProtocol::IsoOnTcp => ApplicationNaiveProtocol::IsoOnTcp,
        }
    }
}

// 层 -> 协议类型
impl From<LinkLayer> for LinkProtocol {
    #[inline]
    fn from(link_layer: LinkLayer) -> Self {
        match link_layer {
            LinkLayer::Ethernet(_) => LinkProtocol::Ethernet,
        }
    }
}

impl From<LinkLayer> for ProtocolType {
    #[inline(always)]
    fn from(link_layer: LinkLayer) -> Self {
        ProtocolType::Link(link_layer.into())
    }
}

impl<'a> From<NetworkLayer<'a>> for NetworkProtocol {
    #[inline]
    fn from(net_layer: NetworkLayer<'a>) -> Self {
        match net_layer {
            NetworkLayer::Ipv4(_) => NetworkProtocol::Ipv4,
            NetworkLayer::Ipv6(_) => NetworkProtocol::Ipv6,
            NetworkLayer::Goose(_) => NetworkProtocol::Goose,
            NetworkLayer::Vlan(_) => NetworkProtocol::Vlan,
        }
    }
}

impl<'a> From<NetworkLayer<'a>> for ProtocolType {
    #[inline(always)]
    fn from(net_layer: NetworkLayer<'a>) -> Self {
        ProtocolType::Network(net_layer.into())
    }
}

impl<'a> From<TransportLayer<'a>> for TransportProtocol {
    #[inline]
    fn from(trans_layer: TransportLayer<'a>) -> Self {
        match trans_layer {
            TransportLayer::Tcp(_) => TransportProtocol::Tcp,
            TransportLayer::Udp(_) => TransportProtocol::Udp,
            TransportLayer::Sv(_) => TransportProtocol::Sv,
        }
    }
}

impl<'a> From<TransportLayer<'a>> for ProtocolType {
    #[inline(always)]
    fn from(trans_layer: TransportLayer<'a>) -> Self {
        ProtocolType::Transport(trans_layer.into())
    }
}

impl<'a> From<ApplicationLayer<'a>> for ApplicationProtocol {
    #[inline]
    fn from(app_layer: ApplicationLayer<'a>) -> Self {
        match app_layer {
            ApplicationLayer::ModbusReq(_) => ApplicationProtocol::ModbusReq,
            ApplicationLayer::ModbusRsp(_) => ApplicationProtocol::ModbusRsp,
            ApplicationLayer::FinsTcpReq(_) => ApplicationProtocol::FinsTcpReq,
            ApplicationLayer::FinsTcpRsp(_) => ApplicationProtocol::FinsTcpRsp,
            ApplicationLayer::FinsUdpReq(_) => ApplicationProtocol::FinsUdpReq,
            ApplicationLayer::FinsUdpRsp(_) => ApplicationProtocol::FinsUdpRsp,
            ApplicationLayer::Mms(_) => ApplicationProtocol::Mms,
            ApplicationLayer::S7comm(_) => ApplicationProtocol::S7comm,
            ApplicationLayer::Bacnet(_) => ApplicationProtocol::Bacnet,
            ApplicationLayer::Dnp3(_) => ApplicationProtocol::Dnp3,
            ApplicationLayer::Iec104(_) => ApplicationProtocol::Iec104,
            ApplicationLayer::Opcua(_) => ApplicationProtocol::Opcua,
            ApplicationLayer::Http(_) => ApplicationProtocol::Http,
            ApplicationLayer::IsoOnTcp(_) => ApplicationProtocol::IsoOnTcp,
        }
    }
}

impl<'a> From<ApplicationLayer<'a>> for ProtocolType {
    #[inline(always)]
    fn from(app_layer: ApplicationLayer<'a>) -> Self {
        ProtocolType::Application(app_layer.into())
    }
}
