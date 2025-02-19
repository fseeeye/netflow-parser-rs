use std::net::IpAddr;

use tracing::debug;

use crate::surule::{
    elements::Direction, SuruleFlowOption, SurulePayloadOption, TcpSurule, UdpSurule,
};

pub trait SuruleDetector {
    type Proto<'a>;
    fn detect_header(&self, dst_ip: &IpAddr, dst_port: u16, src_ip: &IpAddr, src_port: u16)
        -> bool;
    fn detect_option<'a>(&self, _: Self::Proto<'a>) -> bool;
}

impl SuruleDetector for TcpSurule {
    type Proto<'a> = &'a [u8];

    fn detect_header(
        &self,
        dst_ip: &IpAddr,
        dst_port: u16,
        src_ip: &IpAddr,
        src_port: u16,
    ) -> bool {
        match self.direction {
            Direction::Uni => {
                // Warning: 目前 Suricata 规则只支持 IPv4 协议，所以默认放过所有 IPv6 协议
                if let IpAddr::V4(dst_ipv4) = dst_ip {
                    if !self.dst_addr.check(dst_ipv4) {
                        return false;
                    }
                }
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
                }
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

    fn detect_option<'a>(&self, payload: Self::Proto<'a>) -> bool {
        let mut detect_ptr = 0;
        // detect payload options
        for payload_option in &self.payload_options {
            match payload_option {
                SurulePayloadOption::Content(c) => {
                    debug!(target: "SURICATA(TcpSurule::detect_option)", ?payload);
                    debug!(target: "SURICATA(TcpSurule::detect_option)", content = ?c);
                    if let Some(p) = c.check(payload, detect_ptr) {
                        detect_ptr = p;
                        continue;
                    } else {
                        return false;
                    }
                }
                SurulePayloadOption::ByteJump(bj) => {
                    if let Some(p) = bj.jump(payload, detect_ptr) {
                        detect_ptr = p;
                        continue;
                    } else {
                        return false;
                    }
                }
                SurulePayloadOption::ByteTest(bt) => {
                    if let Some(p) = bt.check(payload, detect_ptr) {
                        detect_ptr = p;
                        continue;
                    } else {
                        return false;
                    }
                }
                SurulePayloadOption::Dsize(ds) => {
                    if ds.check(payload) == false {
                        return false;
                    }
                }
                SurulePayloadOption::Pcre(pcre) => {
                    if pcre.check(payload) == false {
                        return false;
                    }
                }
                SurulePayloadOption::IsDataAt(ida) => {
                    if ida.check(payload, detect_ptr) == false {
                        return false;
                    }
                }
                _ => {}
            }
        }
        // detect tcp options
        // TODO
        for tcp_option in &self.tcp_options {
            match tcp_option {
                _ => {}
            }
        }
        // detect flow options
        for flow_option in &self.flow_options {
            match flow_option {
                SuruleFlowOption::Flow(_) => {}
                SuruleFlowOption::Flowbits(flowbits) => {
                    if !flowbits.check() {
                        return false;
                    }
                }
            }
        }

        true
    }
}

impl SuruleDetector for UdpSurule {
    type Proto<'a> = &'a [u8];

    fn detect_header(
        &self,
        dst_ip: &IpAddr,
        dst_port: u16,
        src_ip: &IpAddr,
        src_port: u16,
    ) -> bool {
        match self.direction {
            Direction::Uni => {
                if let IpAddr::V4(dst_ipv4) = dst_ip {
                    if !self.dst_addr.check(dst_ipv4) {
                        return false;
                    }
                }
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
                }
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

    fn detect_option<'a>(&self, payload: Self::Proto<'a>) -> bool {
        let mut detect_ptr = 0;
        for payload_option in &self.payload_options {
            // detect payload options
            match payload_option {
                SurulePayloadOption::Content(c) => {
                    if let Some(p) = c.check(payload, detect_ptr) {
                        detect_ptr = p;
                        continue;
                    } else {
                        return false;
                    }
                }
                SurulePayloadOption::ByteJump(bj) => {
                    if let Some(p) = bj.jump(payload, detect_ptr) {
                        detect_ptr = p;
                        continue;
                    } else {
                        return false;
                    }
                }
                SurulePayloadOption::ByteTest(bt) => {
                    if let Some(p) = bt.check(payload, detect_ptr) {
                        detect_ptr = p;
                        continue;
                    } else {
                        return false;
                    }
                }
                SurulePayloadOption::Dsize(ds) => {
                    if ds.check(payload) == false {
                        return false;
                    }
                }
                SurulePayloadOption::Pcre(pcre) => {
                    if pcre.check(payload) == false {
                        return false;
                    }
                }
                SurulePayloadOption::IsDataAt(ida) => {
                    if ida.check(payload, detect_ptr) == false {
                        return false;
                    }
                }
                _ => {}
            }
        }
        // detect udp options
        // TODO
        for udp_option in &self.udp_options {
            match udp_option {
                _ => {}
            }
        }
        // detect flow options
        for flow_option in &self.flow_options {
            match flow_option {
                SuruleFlowOption::Flow(_) => {}
                SuruleFlowOption::Flowbits(flowbits) => {
                    if !flowbits.check() {
                        return false;
                    }
                }
            }
        }
        return true;
    }
}
