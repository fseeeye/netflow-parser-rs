use std::net::IpAddr;

use crate::parsers::MacAddress;

/// LinkLevelPacket是服务于包含link层的packet
/// 实现获取link层常用字段值的方法。
pub trait LinkLevelPacket {
    fn get_dst_mac(&self) -> MacAddress;
    fn get_src_mac(&self) -> MacAddress;
}

/// NetLevelPacket是服务于包含network层的packet
/// 实现获取network层常用字段值的方法。
pub trait NetLevelPacket {
    fn get_dst_ip(&self) -> IpAddr;
    fn get_src_ip(&self) -> IpAddr;
}

/// TransLevelPacket是服务于包含transport层的packet
/// 实现获取transport层常用字段值的方法。
pub trait TransLevelPacket {
    fn get_dst_port(&self) -> u16;
    fn get_src_port(&self) -> u16;
}
