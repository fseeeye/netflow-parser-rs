use std::net::IpAddr;

use crate::{
    errors::ParseError,
    layer::{ApplicationLayer, LinkLayer},
    parsers::MacAddress,
    LinkLevelPacket, NetLevelPacket, NetworkLayer, TransLevelPacket, TransportLayer,
};

/// L1Packet为一种仅包含错误信息的packet
/// 仅针对解析link层错误的情况使用。
#[derive(Debug)]
pub struct L1Packet<'a> {
    pub error: Option<ParseError>,
    pub remain: &'a [u8],
}

/// L2Packet为一种包含link层信息的packet
/// 针对解析network层时出错或者仅包含link层的数据包。
#[derive(Debug)]
pub struct L2Packet<'a> {
    pub link_layer: LinkLayer,
    pub error: Option<ParseError>,
    pub remain: &'a [u8],
}

impl<'a> LinkLevelPacket for L2Packet<'a> {
    fn get_dst_mac(&self) -> MacAddress {
        let LinkLayer::Ethernet(eth) = &self.link_layer;
        eth.dst_mac
    }

    fn get_src_mac(&self) -> MacAddress {
        let LinkLayer::Ethernet(eth) = &self.link_layer;
        eth.src_mac
    }
}

/// L3Packet为一种包含link&network层信息的packet
/// 针对解析transport层时出错或者包含link&network层的数据包。
#[derive(Debug)]
pub struct L3Packet<'a> {
    pub link_layer: LinkLayer,
    pub net_layer: NetworkLayer<'a>,
    pub error: Option<ParseError>,
    pub remain: &'a [u8],
}

impl<'a> LinkLevelPacket for L3Packet<'a> {
    fn get_dst_mac(&self) -> MacAddress {
        let LinkLayer::Ethernet(eth) = &self.link_layer;
        eth.dst_mac
    }

    fn get_src_mac(&self) -> MacAddress {
        let LinkLayer::Ethernet(eth) = &self.link_layer;
        eth.src_mac
    }
}

impl<'a> NetLevelPacket for L3Packet<'a> {
    fn get_dst_ip(&self) -> std::net::IpAddr {
        match &self.net_layer {
            NetworkLayer::Ipv4(ipv4) => IpAddr::V4(ipv4.dst_ip),
            NetworkLayer::Ipv6(ipv6) => IpAddr::V6(ipv6.dst_ip),
        }
    }

    fn get_src_ip(&self) -> IpAddr {
        match &self.net_layer {
            NetworkLayer::Ipv4(ipv4) => IpAddr::V4(ipv4.src_ip),
            NetworkLayer::Ipv6(ipv6) => IpAddr::V6(ipv6.src_ip),
        }
    }
}

/// L4Packet为一种包含link&network&transport层信息的packet
/// 针对解析application层时出错或者包含link&network&transport层的数据包。
#[derive(Debug)]
pub struct L4Packet<'a> {
    pub link_layer: LinkLayer,
    pub net_layer: NetworkLayer<'a>,
    pub trans_layer: TransportLayer<'a>,
    pub error: Option<ParseError>,
    pub remain: &'a [u8],
}

impl<'a> LinkLevelPacket for L4Packet<'a> {
    fn get_dst_mac(&self) -> MacAddress {
        let LinkLayer::Ethernet(eth) = &self.link_layer;
        eth.dst_mac
    }

    fn get_src_mac(&self) -> MacAddress {
        let LinkLayer::Ethernet(eth) = &self.link_layer;
        eth.src_mac
    }
}

impl<'a> NetLevelPacket for L4Packet<'a> {
    fn get_dst_ip(&self) -> std::net::IpAddr {
        match &self.net_layer {
            NetworkLayer::Ipv4(ipv4) => IpAddr::V4(ipv4.dst_ip),
            NetworkLayer::Ipv6(ipv6) => IpAddr::V6(ipv6.dst_ip),
        }
    }

    fn get_src_ip(&self) -> IpAddr {
        match &self.net_layer {
            NetworkLayer::Ipv4(ipv4) => IpAddr::V4(ipv4.src_ip),
            NetworkLayer::Ipv6(ipv6) => IpAddr::V6(ipv6.src_ip),
        }
    }
}

impl<'a> TransLevelPacket for L4Packet<'a> {
    fn get_dst_port(&self) -> u16 {
        match &self.trans_layer {
            TransportLayer::Tcp(tcp) => tcp.dst_port,
            TransportLayer::Udp(udp) => udp.dst_port,
        }
    }

    fn get_src_port(&self) -> u16 {
        match &self.trans_layer {
            TransportLayer::Tcp(tcp) => tcp.src_port,
            TransportLayer::Udp(udp) => udp.src_port,
        }
    }
}

/// L5Packet为一种包含link&network&transport&application层信息的packet
/// 针对包含link&network&transport&application层的数据包。
#[derive(Debug)]
pub struct L5Packet<'a> {
    pub link_layer: LinkLayer,
    pub net_layer: NetworkLayer<'a>,
    pub trans_layer: TransportLayer<'a>,
    pub app_layer: ApplicationLayer<'a>,
    pub error: Option<ParseError>,
    pub remain: &'a [u8],
}

impl<'a> LinkLevelPacket for L5Packet<'a> {
    fn get_dst_mac(&self) -> MacAddress {
        let LinkLayer::Ethernet(eth) = &self.link_layer;
        eth.dst_mac
    }

    fn get_src_mac(&self) -> MacAddress {
        let LinkLayer::Ethernet(eth) = &self.link_layer;
        eth.src_mac
    }
}

impl<'a> NetLevelPacket for L5Packet<'a> {
    fn get_dst_ip(&self) -> std::net::IpAddr {
        match &self.net_layer {
            NetworkLayer::Ipv4(ipv4) => IpAddr::V4(ipv4.dst_ip),
            NetworkLayer::Ipv6(ipv6) => IpAddr::V6(ipv6.dst_ip),
        }
    }

    fn get_src_ip(&self) -> IpAddr {
        match &self.net_layer {
            NetworkLayer::Ipv4(ipv4) => IpAddr::V4(ipv4.src_ip),
            NetworkLayer::Ipv6(ipv6) => IpAddr::V6(ipv6.src_ip),
        }
    }
}

impl<'a> TransLevelPacket for L5Packet<'a> {
    fn get_dst_port(&self) -> u16 {
        match &self.trans_layer {
            TransportLayer::Tcp(tcp) => tcp.dst_port,
            TransportLayer::Udp(udp) => udp.dst_port,
        }
    }

    fn get_src_port(&self) -> u16 {
        match &self.trans_layer {
            TransportLayer::Tcp(tcp) => tcp.src_port,
            TransportLayer::Udp(udp) => udp.src_port,
        }
    }
}
