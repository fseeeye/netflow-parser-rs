use std::net::IpAddr;

use crate::{
    field_type::*, 
    LinkProtocol, NetworkProtocol, TransportProtocol, ApplicationProtocol, ApplicationNaiveProtocol
};

/// 错误层
pub trait PhyLevel {
    fn is_error(&self) -> bool;
}

/// LinkLevel服务于包含link层的packet
/// 
/// 实现"获取link层 MAC 字段值"等常用方法。
pub trait LinkLevel: PhyLevel {
    fn get_dst_mac(&self) -> &MacAddress;
    fn get_src_mac(&self) -> &MacAddress;
    fn get_link_type(&self) -> LinkProtocol;
}

/// NetLevel服务于包含network层的packet
/// 
/// 实现"获取network层 IP 字段值"等常用方法。
pub trait NetLevel: LinkLevel {
    fn get_dst_ip(&self) -> IpAddr;
    fn get_src_ip(&self) -> IpAddr;
    fn get_net_type(&self) -> NetworkProtocol;
}

/// TransLevel服务于包含transport层的packet
/// 
/// 实现"获取transport层常用字段值"等常用方法。
pub trait TransLevel: NetLevel {
    fn get_dst_port(&self) -> u16;
    fn get_src_port(&self) -> u16;
    fn get_tran_type(&self) -> TransportProtocol;
}

/// AppLevel服务于包含application层的packet
/// 
/// 实现"获取application层协议类型"等常用方法。
pub trait AppLevel: TransLevel {
    fn get_app_type(&self) -> ApplicationProtocol;
    #[inline(always)]
    fn get_app_naive_type(&self) -> ApplicationNaiveProtocol {
        self.get_app_type().into()
    }
}
