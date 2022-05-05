use serde::{Deserialize, Serialize};

use parsing_rule::{RuleAction, Direction};
use parsing_parser::{L5Packet, NetLevel, TransLevel};

use crate::{detect::IcsRuleDetector, rule_utils::*};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct IcsRuleBasis {
    pub active: bool,
    pub rid: usize,
    // mac
    pub action: RuleAction,
    #[serde(rename = "src")]
    pub src_ip: Option<Ipv4AddressVec>,
    #[serde(rename = "sport")]
    pub src_port: Option<NumVec<u16>>,
    #[serde(rename = "dire")]
    pub dir: Direction,
    #[serde(rename = "dst")]
    pub dst_ip: Option<Ipv4AddressVec>,
    #[serde(rename = "dport")]
    pub dst_port: Option<NumVec<u16>>,
    pub msg: String,
}

impl IcsRuleDetector for IcsRuleBasis {
    fn detect(&self, l5: &L5Packet) -> bool {
        if !self.active {
            return false;
        }

        let packet_src_ip = match l5.get_src_ip() {
            Some(o) => o,
            None => return false
        };
        let packet_dst_ip =  match l5.get_dst_ip() {
            Some(o) => o,
            None => return false
        };
        let packet_src_port = match l5.get_src_port() {
            Some(o) => o,
            None => return false
        };
        let packet_dst_port = match l5.get_dst_port() {
            Some(o) => o,
            None => return false
        };

        match self.dir {
            Direction::Uni => {
                // 如果rules该字段设置了值，并且和packet相应字段不匹配，返回false
                if self.src_ip.is_some() && !self.src_ip.as_ref().unwrap().contain(&packet_src_ip) {
                    return false;
                }
                if self.dst_ip.is_some() && !self.dst_ip.as_ref().unwrap().contain(&packet_dst_ip) {
                    return false;
                }
                if self.src_port.is_some() && !self.src_port.as_ref().unwrap().contain(packet_src_port) {
                    return false;
                }
                if self.dst_port.is_some() && !self.dst_port.as_ref().unwrap().contain(packet_dst_port) {
                    return false;
                }
            }
            Direction::Bi => {
                if (self.src_ip.is_some() && !self.src_ip.as_ref().unwrap().contain(&packet_src_ip))
                    && (self.dst_ip.is_some() && !self.dst_ip.as_ref().unwrap().contain(&packet_dst_ip))
                {
                    if !self.src_ip.as_ref().unwrap().contain(&packet_dst_ip) && !self.dst_ip.as_ref().unwrap().contain(&packet_src_ip)
                    {
                        return false;
                    }
                }
                if (self.src_port.is_some() && !self.src_port.as_ref().unwrap().contain(packet_src_port))
                    && (self.dst_port.is_some() && !self.dst_port.as_ref().unwrap().contain(packet_dst_port))
                {
                    if !self.src_port.as_ref().unwrap().contain(packet_dst_port)
                        && !self.dst_port.as_ref().unwrap().contain(packet_src_port)
                    {
                        return false;
                    }
                }
            }
        }
        // 所有Some(...)均和packet相应字段匹配 或 rules全为None，返回true
        true
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, str::FromStr};

    use parsing_parser::{
        parsers::{
            modbus_rsp::{Data::ReadDiscreteInputs, MbapHeader, PDU},
            EthernetHeader, Ipv4Header, ModbusRspHeader, TcpHeader,
        },
        ApplicationLayer, LinkLayer, MacAddress, NetworkLayer, TransportLayer,
    };

    use super::*;

    #[test]
    fn detect_ics_rule_basis() {
        let l5 = L5Packet {
            link_layer: LinkLayer::Ethernet(EthernetHeader {
                dst_mac: MacAddress([32, 16, 21, 233, 21, 1]),
                src_mac: MacAddress([32, 16, 21, 233, 21, 2]),
                link_type: 2048,
            }),
            network_layer: NetworkLayer::Ipv4(Ipv4Header {
                src_ip: Ipv4Addr::from_str("192.168.0.2").unwrap(),
                dst_ip: Ipv4Addr::from_str("192.168.0.3").unwrap(),
                version: 4,
                header_length: 5,
                diff_service: 0,
                ecn: 0,
                total_length: 131,
                id: 52555,
                flags: 2,
                fragment_offset: 0,
                ttl: 64,
                protocol: 6,
                checksum: 38996,
                options: None,
            }),
            transport_layer: TransportLayer::Tcp(TcpHeader {
                src_port: 502,
                dst_port: 53211,
                seq: 1175987464,
                ack: 3947317609,
                header_length: 5,
                reserved: 0,
                flags: 24,
                window_size: 256,
                checksum: 45344,
                urgent_pointer: 0,
                options: None,
                padding: None,
                payload: &[1, 0, 0, 0, 0, 4, 1, 2, 1, 0],
            }),
            application_layer: ApplicationLayer::ModbusRsp(ModbusRspHeader {
                mbap_header: MbapHeader {
                    transaction_id: 256,
                    protocol_id: 0,
                    length: 4,
                    unit_id: 1,
                },
                pdu: PDU {
                    function_code: 2,
                    data: ReadDiscreteInputs {
                        byte_count: 1,
                        coil_status: vec![0, 0, 0, 0, 0, 0, 0, 0],
                    },
                },
            }),
            remain: &[],
            error: None,
        };

        let basis_rule = IcsRuleBasis {
            active: true,
            rid: 1,
            action: RuleAction::Alert,
            src_ip: Some(Ipv4AddressVec(vec![Ipv4Address::Addr(Ipv4Addr::from_str("192.168.0.2").unwrap())])),
            src_port: Some(NumVec(vec![Num::Single(502u16)])),
            dir: Direction::Uni,
            dst_ip: Some(Ipv4AddressVec(vec![Ipv4Address::Addr(Ipv4Addr::from_str("192.168.0.3").unwrap())])),
            dst_port: Some(NumVec(vec![Num::Single(53211u16)])),
            msg: "".to_string(),
        };

        assert_eq!(basis_rule.detect(&l5), true);
    }
}
