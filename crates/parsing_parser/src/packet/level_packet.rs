use super::level::{LinkLevel, NetLevel, TransLevel, AppLevel, PhyLevel};
use crate::{
    errors::ParseError,
    field_type::*,
    layer::{ApplicationLayer, LinkLayer, NetworkLayer, TransportLayer},
};

/// L1Packet为一种仅包含错误信息的packet
/// 仅针对解析link层错误的情况使用。
#[derive(Debug)]
pub struct L1Packet<'a> {
    pub error: Option<ParseError>,
    pub remain: &'a [u8],
}

impl<'a> PhyLevel for L1Packet<'a> {
    #[inline(always)]
    fn is_error(&self) -> bool {
        self.error.is_none()
    }
}

/// L2Packet为一种包含link层信息的packet
/// 针对解析network层时出错或者仅包含link层的数据包。
#[derive(Debug)]
pub struct L2Packet<'a> {
    pub link_layer: LinkLayer,
    pub error: Option<ParseError>,
    pub remain: &'a [u8],
}

impl<'a> PhyLevel for L2Packet<'a> {
    #[inline(always)]
    fn is_error(&self) -> bool {
        self.error.is_none()
    }
}

impl<'a> LinkLevel for L2Packet<'a> {
    #[inline(always)]
    fn get_dst_mac(&self) -> &MacAddress {
        self.link_layer.get_dst_mac()
    }

    #[inline(always)]
    fn get_src_mac(&self) -> &MacAddress {
        self.link_layer.get_src_mac()
    }

    #[inline(always)]
    fn get_link_type(&self) -> crate::LinkProtocol {
        self.link_layer.to_owned().into()
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

impl<'a> PhyLevel for L3Packet<'a> {
    #[inline(always)]
    fn is_error(&self) -> bool {
        self.error.is_none()
    }
}

impl<'a> LinkLevel for L3Packet<'a> {
    #[inline(always)]
    fn get_dst_mac(&self) -> &MacAddress {
        self.link_layer.get_dst_mac()
    }

    #[inline(always)]
    fn get_src_mac(&self) -> &MacAddress {
        self.link_layer.get_src_mac()
    }

    #[inline(always)]
    fn get_link_type(&self) -> crate::LinkProtocol {
        self.link_layer.to_owned().into()
    }
}

impl<'a> NetLevel for L3Packet<'a> {
    #[inline(always)]
    fn get_dst_ip(&self) -> IpAddr {
        self.network_layer.get_dst_ip()
    }

    #[inline(always)]
    fn get_src_ip(&self) -> IpAddr {
        self.network_layer.get_src_ip()
    }

    #[inline(always)]
    fn get_net_type(&self) -> crate::NetworkProtocol {
        self.network_layer.to_owned().into()
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

impl<'a> PhyLevel for L4Packet<'a> {
    #[inline(always)]
    fn is_error(&self) -> bool {
        self.error.is_none()
    }
}

impl<'a> LinkLevel for L4Packet<'a> {
    #[inline(always)]
    fn get_dst_mac(&self) -> &MacAddress {
        self.link_layer.get_dst_mac()
    }

    #[inline(always)]
    fn get_src_mac(&self) -> &MacAddress {
        self.link_layer.get_src_mac()
    }

    #[inline(always)]
    fn get_link_type(&self) -> crate::LinkProtocol {
        self.link_layer.to_owned().into()
    }
}

impl<'a> NetLevel for L4Packet<'a> {
    #[inline(always)]
    fn get_dst_ip(&self) -> IpAddr {
        self.network_layer.get_dst_ip()
    }

    #[inline(always)]
    fn get_src_ip(&self) -> IpAddr {
        self.network_layer.get_src_ip()
    }

    #[inline(always)]
    fn get_net_type(&self) -> crate::NetworkProtocol {
        self.network_layer.to_owned().into()
    }
}

impl<'a> TransLevel for L4Packet<'a> {
    #[inline(always)]
    fn get_dst_port(&self) -> u16 {
        self.transport_layer.get_dst_port()
    }

    #[inline(always)]
    fn get_src_port(&self) -> u16 {
        self.transport_layer.get_src_port()
    }

    #[inline(always)]
    fn get_tran_type(&self) -> crate::TransportProtocol {
        self.transport_layer.to_owned().into()
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

impl<'a> PhyLevel for L5Packet<'a> {
    #[inline(always)]
    fn is_error(&self) -> bool {
        self.error.is_none()
    }
}

impl<'a> LinkLevel for L5Packet<'a> {
    #[inline(always)]
    fn get_dst_mac(&self) -> &MacAddress {
        self.link_layer.get_dst_mac()
    }

    #[inline(always)]
    fn get_src_mac(&self) -> &MacAddress {
        self.link_layer.get_src_mac()
    }

    #[inline(always)]
    fn get_link_type(&self) -> crate::LinkProtocol {
        self.link_layer.to_owned().into()
    }
}

impl<'a> NetLevel for L5Packet<'a> {
    #[inline(always)]
    fn get_dst_ip(&self) -> IpAddr {
        self.network_layer.get_dst_ip()
    }

    #[inline(always)]
    fn get_src_ip(&self) -> IpAddr {
        self.network_layer.get_src_ip()
    }

    #[inline(always)]
    fn get_net_type(&self) -> crate::NetworkProtocol {
        self.network_layer.to_owned().into()
    }
}

impl<'a> TransLevel for L5Packet<'a> {
    #[inline(always)]
    fn get_dst_port(&self) -> u16 {
        self.transport_layer.get_dst_port()
    }

    #[inline(always)]
    fn get_src_port(&self) -> u16 {
        self.transport_layer.get_src_port()
    }

    #[inline(always)]
    fn get_tran_type(&self) -> crate::TransportProtocol {
        self.transport_layer.to_owned().into()
    }
}

impl<'a> AppLevel for L5Packet<'a> {
    #[inline(always)]
    fn get_app_type(&self) -> crate::ApplicationProtocol {
        self.application_layer.to_owned().into()
    }
}