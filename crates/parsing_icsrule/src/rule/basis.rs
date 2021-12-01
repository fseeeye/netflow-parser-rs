use serde::{Deserialize, Serialize};

use std::net::IpAddr;

use parsing_parser::{L5Packet, NetLevel, TransLevel};

use crate::detect::IcsRuleDetector;


#[derive(Serialize, Deserialize, Debug)]
pub struct IcsRuleBasis {
    pub rid: u32,
    pub action: Action,
    pub src_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dir: Direction,
    pub dst_ip: Option<IpAddr>,
    pub dst_port: Option<u16>,
    pub msg: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Alert,
    Drop,
    Reject,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Direction {
    #[serde(rename = "->")]
    Uni,
    #[serde(rename = "<>")]
    Bi,
}

impl IcsRuleDetector for IcsRuleBasis {
    fn detect(&self, l5: &L5Packet) -> bool {
        let packet_src_ip = l5.get_src_ip();
        let packet_dst_ip = l5.get_dst_ip();
        let packet_src_port = l5.get_src_port();
        let packet_dst_port = l5.get_dst_port();

        match self.dir {
            Direction::Uni => {
                // 如果rules该字段设置了值，并且和packet相应字段不匹配，返回false
                if self.src_ip.is_some() && self.src_ip != packet_src_ip {
                    return false;
                }
                if self.dst_ip.is_some() && self.dst_ip != packet_dst_ip {
                    return false;
                }
                if self.src_port.is_some() && self.src_port != packet_src_port {
                    return false;
                }
                if self.dst_port.is_some() && self.dst_port != packet_dst_port {
                    return false;
                }
            },
            Direction::Bi => {
                if self.src_ip.is_some() && self.src_ip != packet_src_ip && self.src_ip != packet_dst_ip {
                    return false;
                }
                if self.dst_ip.is_some() && self.dst_ip != packet_dst_ip && self.dst_ip != packet_src_ip {
                    return false;
                }
                if self.src_port.is_some() && self.src_port != packet_src_port && self.src_port != packet_dst_port {
                    return false;
                }
                if self.dst_port.is_some() && self.dst_port != packet_dst_port && self.src_port != packet_dst_port {
                    return false;
                }
            }
        }
        // 所有Some(...)均和packet相应字段匹配 或 rules全为None，返回true
        true
    }
}
