use crate::{
    errors::ParseError,
    layer::{LinkLayer, NetworkLayer, TransportLayer, ApplicationLayer},
    field_type::*, 
};
use super::level::{ LinkLevel, NetLevel, TransLevel };

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

#[allow(unreachable_patterns)]
impl<'a> LinkLevel for L2Packet<'a> {
    fn get_dst_mac(&self) -> Option<MacAddress> {
        match &self.link_layer {
            LinkLayer::Ethernet(eth) => Some(eth.dst_mac),
            _ => None
        }
    }

    fn get_src_mac(&self) -> Option<MacAddress> {
        match &self.link_layer {
            LinkLayer::Ethernet(eth) => Some(eth.src_mac),
            _ => None
        }
    }
}

/// L3Packet为一种包含link&network层信息的packet
/// 针对解析transport层时出错或者包含link&network层的数据包。
#[derive(Debug)]
pub struct L3Packet<'a> {
    pub link_layer: LinkLayer,
    pub network_layer: NetworkLayer<'a>,
    pub error: Option<ParseError>,
    pub remain: &'a [u8],
}

#[allow(unreachable_patterns)]
impl<'a> LinkLevel for L3Packet<'a> {
    fn get_dst_mac(&self) -> Option<MacAddress> {
        match &self.link_layer {
            LinkLayer::Ethernet(eth) => Some(eth.dst_mac),
            _ => None
        }
    }

    fn get_src_mac(&self) -> Option<MacAddress> {
        match &self.link_layer {
            LinkLayer::Ethernet(eth) => Some(eth.src_mac),
            _ => None
        }
    }
}

#[allow(unreachable_patterns)]
impl<'a> NetLevel for L3Packet<'a> {
    fn get_dst_ip(&self) -> Option<IpAddr> {
        match &self.network_layer {
            NetworkLayer::Ipv4(ipv4) => Some(IpAddr::V4(ipv4.dst_ip)),
            NetworkLayer::Ipv6(ipv6) => Some(IpAddr::V6(ipv6.dst_ip)),
            _ => None,
        }
    }

    fn get_src_ip(&self) -> Option<IpAddr> {
        match &self.network_layer {
            NetworkLayer::Ipv4(ipv4) => Some(IpAddr::V4(ipv4.src_ip)),
            NetworkLayer::Ipv6(ipv6) => Some(IpAddr::V6(ipv6.src_ip)),
            _ => None,
        }
    }
}

/// L4Packet为一种包含link&network&transport层信息的packet
/// 针对解析application层时出错或者包含link&network&transport层的数据包。
#[derive(Debug)]
pub struct L4Packet<'a> {
    pub link_layer: LinkLayer,
    pub network_layer: NetworkLayer<'a>,
    pub transport_layer: TransportLayer<'a>,
    pub error: Option<ParseError>,
    pub remain: &'a [u8],
}

#[allow(unreachable_patterns)]
impl<'a> LinkLevel for L4Packet<'a> {
    fn get_dst_mac(&self) -> Option<MacAddress> {
        match &self.link_layer {
            LinkLayer::Ethernet(eth) => Some(eth.dst_mac),
            _ => None
        }
    }

    fn get_src_mac(&self) -> Option<MacAddress> {
        match &self.link_layer {
            LinkLayer::Ethernet(eth) => Some(eth.src_mac),
            _ => None
        }
    }
}

#[allow(unreachable_patterns)]
impl<'a> NetLevel for L4Packet<'a> {
    fn get_dst_ip(&self) -> Option<IpAddr> {
        match &self.network_layer {
            NetworkLayer::Ipv4(ipv4) => Some(IpAddr::V4(ipv4.dst_ip)),
            NetworkLayer::Ipv6(ipv6) => Some(IpAddr::V6(ipv6.dst_ip)),
            _ => None,
        }
    }

    fn get_src_ip(&self) -> Option<IpAddr> {
        match &self.network_layer {
            NetworkLayer::Ipv4(ipv4) => Some(IpAddr::V4(ipv4.src_ip)),
            NetworkLayer::Ipv6(ipv6) => Some(IpAddr::V6(ipv6.src_ip)),
            _ => None,
        }
    }
}

#[allow(unreachable_patterns)]
impl<'a> TransLevel for L4Packet<'a> {
    fn get_dst_port(&self) -> Option<u16> {
        match &self.transport_layer {
            TransportLayer::Tcp(tcp) => Some(tcp.dst_port),
            TransportLayer::Udp(udp) => Some(udp.dst_port),
            _ => None,
        }
    }

    fn get_src_port(&self) -> Option<u16> {
        match &self.transport_layer {
            TransportLayer::Tcp(tcp) => Some(tcp.src_port),
            TransportLayer::Udp(udp) => Some(udp.src_port),
            _ => None,
        }
    }
}

/// L5Packet为一种包含link&network&transport&application层信息的packet
/// 针对包含link&network&transport&application层的数据包。
#[derive(Debug)]
pub struct L5Packet<'a> {
    pub link_layer: LinkLayer,
    pub network_layer: NetworkLayer<'a>,
    pub transport_layer: TransportLayer<'a>,
    pub application_layer: ApplicationLayer<'a>,
    pub error: Option<ParseError>,
    pub remain: &'a [u8],
}

#[allow(unreachable_patterns)]
impl<'a> LinkLevel for L5Packet<'a> {
    fn get_dst_mac(&self) -> Option<MacAddress> {
        match &self.link_layer {
            LinkLayer::Ethernet(eth) => Some(eth.dst_mac),
            _ => None
        }
    }

    fn get_src_mac(&self) -> Option<MacAddress> {
        match &self.link_layer {
            LinkLayer::Ethernet(eth) => Some(eth.src_mac),
            _ => None
        }
    }
}

#[allow(unreachable_patterns)]
impl<'a> NetLevel for L5Packet<'a> {
    fn get_dst_ip(&self) -> Option<IpAddr> {
        match &self.network_layer {
            NetworkLayer::Ipv4(ipv4) => Some(IpAddr::V4(ipv4.dst_ip)),
            NetworkLayer::Ipv6(ipv6) => Some(IpAddr::V6(ipv6.dst_ip)),
            _ => None,
        }
    }

    fn get_src_ip(&self) -> Option<IpAddr> {
        match &self.network_layer {
            NetworkLayer::Ipv4(ipv4) => Some(IpAddr::V4(ipv4.src_ip)),
            NetworkLayer::Ipv6(ipv6) => Some(IpAddr::V6(ipv6.src_ip)),
            _ => None,
        }
    }
}

#[allow(unreachable_patterns)]
impl<'a> TransLevel for L5Packet<'a> {
    fn get_dst_port(&self) -> Option<u16> {
        match &self.transport_layer {
            TransportLayer::Tcp(tcp) => Some(tcp.dst_port),
            TransportLayer::Udp(udp) => Some(udp.dst_port),
            _ => None,
        }
    }

    fn get_src_port(&self) -> Option<u16> {
        match &self.transport_layer {
            TransportLayer::Tcp(tcp) => Some(tcp.src_port),
            TransportLayer::Udp(udp) => Some(udp.src_port),
            _ => None,
        }
    }
}
