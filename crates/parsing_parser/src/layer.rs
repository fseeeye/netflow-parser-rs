//! Layer是包含协议解析结果的数据结构
use std::net::IpAddr;

use crate::{
    parsers::*, 
    field_type::MacAddress
};

/// LinkLayer是表示link层内容的类型。
#[derive(Debug, PartialEq, Clone)]
pub enum LinkLayer {
    Ethernet(EthernetHeader),
}

impl LinkLayer {
    #[inline]
    pub fn get_dst_mac(&self) -> &MacAddress {
        match &self {
            LinkLayer::Ethernet(eth) => &eth.dst_mac,
        }
    }

    #[inline]
    pub fn get_src_mac(&self) -> &MacAddress {
        match &self {
            LinkLayer::Ethernet(eth) => &eth.src_mac,
        }
    }
}

/// NetworkLayer是表示network层内容的类型。
#[derive(Debug, PartialEq, Clone)]
pub enum NetworkLayer<'a> {
    Ipv4(Ipv4Header<'a>),
    Ipv6(Ipv6Header<'a>),
}

impl<'a> NetworkLayer<'a> {
    #[inline]
    pub fn get_dst_ip(&self) -> IpAddr {
        match self {
            NetworkLayer::Ipv4(ipv4) => IpAddr::V4(ipv4.dst_ip),
            NetworkLayer::Ipv6(ipv6) => IpAddr::V6(ipv6.dst_ip),
        }
    }

    #[inline]
    pub fn get_src_ip(&self) -> IpAddr {
        match self {
            NetworkLayer::Ipv4(ipv4) => IpAddr::V4(ipv4.src_ip),
            NetworkLayer::Ipv6(ipv6) => IpAddr::V6(ipv6.src_ip),
        }
    }
}

/// TransportLayer是表示transport层内容的类型。
#[derive(Debug, PartialEq, Clone)]
pub enum TransportLayer<'a> {
    Tcp(TcpHeader<'a>),
    Udp(UdpHeader),
}

impl<'a> TransportLayer<'a> {
    #[inline]
    pub fn get_dst_port(&self) -> u16 {
        match self {
            TransportLayer::Tcp(tcp) => tcp.dst_port,
            TransportLayer::Udp(udp) => udp.dst_port,
        }
    }

    #[inline]
    pub fn get_src_port(&self) -> u16 {
        match self {
            TransportLayer::Tcp(tcp) => tcp.src_port,
            TransportLayer::Udp(udp) => udp.src_port,
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