use std::net::IpAddr;

use crate::field_type::*;


/// LinkLevel服务于包含link层的packet
/// 实现获取link层常用字段值的方法。
pub trait LinkLevel {
    fn get_dst_mac(&self) -> Option<MacAddress>;
    fn get_src_mac(&self) -> Option<MacAddress>;
}

/// NetLevel服务于包含network层的packet
/// 实现获取network层常用字段值的方法。
pub trait NetLevel {
    fn get_dst_ip(&self) -> Option<IpAddr>;
    fn get_src_ip(&self) -> Option<IpAddr>;
}

/// TransLevel服务于包含transport层的packet
/// 实现获取transport层常用字段值的方法。
pub trait TransLevel {
    fn get_dst_port(&self) -> Option<u16>;
    fn get_src_port(&self) -> Option<u16>;
}
