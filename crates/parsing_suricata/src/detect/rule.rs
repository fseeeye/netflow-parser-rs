use std::net::IpAddr;

use crate::surule::{elements::Direction, TcpSurule, UdpSurule, SuruleFlowOption};

use super::elements::{SuruleElementDetector, SuruleElementSimpleDetector};


pub trait SuruleDetector {
    type Proto;
    fn detect_header(
        &self,
        dst_ip: &IpAddr,
        dst_port: &u16,
        src_ip: &IpAddr,
        src_port: &u16,
    ) -> bool;
    fn detect_option(&self, _: Self::Proto) -> bool;
}

impl SuruleDetector for TcpSurule {
    type Proto = u8;

    fn detect_header(
        &self,
        dst_ip: &IpAddr,
        dst_port: &u16,
        src_ip: &IpAddr,
        src_port: &u16,
    ) -> bool {
        match self.direction {
            Direction::Uni => {
                // Warning: 目前 Suricata 规则只支持 IPv4 协议，所以默认放过所有 IPv6 协议
                if let IpAddr::V4(dst_ipv4) = dst_ip {
                    if !self.dst_addr.check(dst_ipv4) {
                        return false;
                    }
                };
                if let IpAddr::V4(src_ipv4) = src_ip {
                    if !self.src_addr.check(src_ipv4) {
                        return false;
                    }
                }
                if !self.dst_port.check(dst_port) {
                    return false;
                }
                if !self.src_port.check(src_port) {
                    return false;
                }
            }
            Direction::Bi => {
                if let IpAddr::V4(dst_ipv4) = dst_ip {
                    if !self.dst_addr.check(dst_ipv4) && !self.src_addr.check(dst_ipv4) {
                        return false;
                    }
                };
                if let IpAddr::V4(src_ipv4) = src_ip {
                    if !self.src_addr.check(src_ipv4) && !self.dst_addr.check(src_ipv4) {
                        return false;
                    }
                }
                if !self.dst_port.check(dst_port) && !self.src_port.check(dst_port) {
                    return false;
                }
                if !self.src_port.check(src_port) && !self.dst_port.check(src_port) {
                    return false;
                }
            }
        }
        true
    }

    // TODO
    fn detect_option(&self, _: Self::Proto) -> bool {
        for payload_option in &self.payload_options {
            match payload_option {
                _ => {}
            }
        }
        for tcp_option in &self.tcp_options {
            match tcp_option {
                _ => {}
            }
        }
        for flow_option in &self.flow_options {
            match flow_option {
                SuruleFlowOption::Flow(_) => {},
                SuruleFlowOption::Flowbits(flowbits) => {
                    if !flowbits.check_simple() {
                        return false
                    }
                }
            }
        }

        true
    }
}

impl SuruleDetector for UdpSurule {
    type Proto = u8;

    fn detect_header(
        &self,
        dst_ip: &IpAddr,
        dst_port: &u16,
        src_ip: &IpAddr,
        src_port: &u16,
    ) -> bool {
        match self.direction {
            Direction::Uni => {
                if let IpAddr::V4(dst_ipv4) = dst_ip {
                    if !self.dst_addr.check(dst_ipv4) {
                        return false;
                    }
                };
                if let IpAddr::V4(src_ipv4) = src_ip {
                    if !self.src_addr.check(src_ipv4) {
                        return false;
                    }
                }
                if !self.dst_port.check(dst_port) {
                    return false;
                }
                if !self.src_port.check(src_port) {
                    return false;
                }
            }
            Direction::Bi => {
                if let IpAddr::V4(dst_ipv4) = dst_ip {
                    if !self.dst_addr.check(dst_ipv4) && !self.src_addr.check(dst_ipv4) {
                        return false;
                    }
                };
                if let IpAddr::V4(src_ipv4) = src_ip {
                    if !self.src_addr.check(src_ipv4) && !self.dst_addr.check(src_ipv4) {
                        return false;
                    }
                }
                if !self.dst_port.check(dst_port) && !self.src_port.check(dst_port) {
                    return false;
                }
                if !self.src_port.check(src_port) && !self.dst_port.check(src_port) {
                    return false;
                }
            }
        }
        true
    }

    // TODO
    fn detect_option(&self, _: Self::Proto) -> bool {
        for payload_option in &self.payload_options {
            match payload_option {
                _ => {}
            }
        }
        for udp_option in &self.udp_options {
            match udp_option {
                _ => {}
            }
        }
        for flow_option in &self.flow_options {
            match flow_option {
                _ => {}
            }
        }
        return true;
    }
}
