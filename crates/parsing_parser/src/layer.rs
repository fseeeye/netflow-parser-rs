//! Layer是包含协议解析结果的数据结构
use std::net::IpAddr;

use crate::{field_type::MacAddress, parsers::*};

/// LinkLayer是表示link层内容的类型。
#[derive(Debug, PartialEq, Clone)]
pub enum LinkLayer {
    Ethernet(EthernetHeader),
}

impl LinkLayer {
    #[inline]
    pub fn get_dst_mac(&self) -> Option<MacAddress> {
        match &self {
            LinkLayer::Ethernet(eth) => Some(eth.dst_mac),
        }
    }

    #[inline]
    pub fn get_src_mac(&self) -> Option<MacAddress> {
        match &self {
            LinkLayer::Ethernet(eth) => Some(eth.src_mac),
        }
    }
}

/// NetworkLayer是表示network层内容的类型。
#[derive(Debug, PartialEq, Clone)]
pub enum NetworkLayer<'a> {
    Ipv4(Ipv4Header<'a>),
    Ipv6(Ipv6Header<'a>),
    Goose(GooseHeader<'a>),
}

impl<'a> NetworkLayer<'a> {
    #[inline]
    pub fn get_dst_ip(&self) -> Option<IpAddr> {
        match self {
            NetworkLayer::Ipv4(ipv4) => Some(IpAddr::V4(ipv4.dst_ip)),
            NetworkLayer::Ipv6(ipv6) => Some(IpAddr::V6(ipv6.dst_ip)),
            NetworkLayer::Goose(_) => None,
        }
    }

    #[inline]
    pub fn get_src_ip(&self) -> Option<IpAddr> {
        match self {
            NetworkLayer::Ipv4(ipv4) => Some(IpAddr::V4(ipv4.src_ip)),
            NetworkLayer::Ipv6(ipv6) => Some(IpAddr::V6(ipv6.src_ip)),
            NetworkLayer::Goose(_) => None,
        }
    }
}

/// TransportLayer是表示transport层内容的类型。
#[derive(Debug, PartialEq, Clone)]
pub enum TransportLayer<'a> {
    Tcp(TcpHeader<'a>),
    Udp(UdpHeader<'a>),
}

impl<'a> TransportLayer<'a> {
    #[inline]
    pub fn get_dst_port(&self) -> Option<u16> {
        match self {
            TransportLayer::Tcp(tcp) => Some(tcp.dst_port),
            TransportLayer::Udp(udp) => Some(udp.dst_port),
        }
    }

    #[inline]
    pub fn get_src_port(&self) -> Option<u16> {
        match self {
            TransportLayer::Tcp(tcp) => Some(tcp.src_port),
            TransportLayer::Udp(udp) => Some(udp.src_port),
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
    Dnp3(Dnp3Header),
    Iec104(Iec104Header),
    Opcua(OpcuaHeader<'a>),
    Http(HttpHeader<'a>),
    IsoOnTcp(IsoOnTcpHeader),
}
