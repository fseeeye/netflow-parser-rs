use parsing_parser::{AppLevel, NetLevel, QuinPacket, TransLevel, TransportLayer};
use parsing_rule::*;
use tracing::debug;

use super::rule::SuruleDetector;
use crate::surule::{elements::Action, VecSurules};

impl Into<RuleAction> for Action {
    fn into(self) -> RuleAction {
        match self {
            Action::Alert => RuleAction::Alert,
            Action::Drop => RuleAction::Drop,
            Action::Pass => RuleAction::Pass,
            Action::Reject | Action::RejectBoth | Action::RejectDst | Action::RejectSrc => {
                RuleAction::Reject
            }
        }
    }
}

impl RulesDetector for VecSurules {
    fn detect(&self, packet: &QuinPacket) -> DetectResult {
        // Warning: 目前数据包规则匹配过程中，直接返回第一个匹配到的规则的 Action，无法设置单个规则优先级。

        // 判断该数据包为第几层协议，为其分配相应的规则
        match packet {
            QuinPacket::L4(l4) => {
                let dst_ip = l4.get_dst_ip();
                let dst_port = l4.get_dst_port();
                let src_ip = l4.get_src_ip();
                let src_port = l4.get_src_port();

                match l4.transport_layer {
                    TransportLayer::Tcp(tcp) => {
                        // detect tcp suricata rules for this packet
                        let tcp_rules = &self.tcp_rules;
                        for tcp_rule in tcp_rules {
                            debug!(target: "SURICATA(VecSurules::detect)", "checking TCP Rule: {:?}", &tcp_rule);
                            if tcp_rule.detect_header(&dst_ip, dst_port, &src_ip, src_port) {
                                // TODO
                                if tcp_rule.detect_option(tcp.payload) {
                                    debug!(target: "SURICATA(VecSurules::detect)", "HIT current TCP Rule!");
                                    return DetectResult::Hit(1, tcp_rule.action.clone().into());
                                }
                            }
                        }
                    }
                    TransportLayer::Udp(udp) => {
                        // detect udp suricata rules for this packet
                        let udp_rules = &self.udp_rules;
                        for udp_rule in udp_rules {
                            if udp_rule.detect_header(&dst_ip, dst_port, &src_ip, src_port) {
                                // TODO
                                if udp_rule.detect_option(udp.payload) {
                                    debug!(target: "SURICATA(VecSurules::detect)", "HIT current UDP Rule: {:?}", &udp_rule);
                                    return DetectResult::Hit(1, udp_rule.action.clone().into());
                                }
                            }
                        }
                    }
                }
                debug!(target: "SURICATA(VecSurules::detect)", "MISS current Rule!");
                DetectResult::Miss
            }

            QuinPacket::L5(l5) => {
                let dst_ip = l5.get_dst_ip();
                let dst_port = l5.get_dst_port();
                let src_ip = l5.get_src_ip();
                let src_port = l5.get_src_port();

                // Warning: 传输层规则优先级高于应用层规则
                match l5.transport_layer {
                    TransportLayer::Tcp(tcp) => {
                        // detect tcp suricata rules for this packet
                        let tcp_rules = &self.tcp_rules;
                        for tcp_rule in tcp_rules {
                            debug!(target: "SURICATA(VecSurules::detect)", "checking TCP Rule: {:?}", &tcp_rule);
                            if tcp_rule.detect_header(&dst_ip, dst_port, &src_ip, src_port) {
                                // TODO
                                if tcp_rule.detect_option(tcp.payload) {
                                    debug!(target: "SURICATA(VecSurules::detect)", "HIT current TCP Rule!");
                                    return DetectResult::Hit(1, tcp_rule.action.clone().into());
                                }
                            }
                        }
                    }
                    TransportLayer::Udp(udp) => {
                        // detect udp suricata rules for this packet
                        let udp_rules = &self.udp_rules;
                        for udp_rule in udp_rules {
                            if udp_rule.detect_header(&dst_ip, dst_port, &src_ip, src_port) {
                                // TODO
                                if udp_rule.detect_option(udp.payload) {
                                    debug!(target: "SURICATA(VecSurules::detect)", "HIT current TCP Rule: {:?}", &udp_rule);
                                    return DetectResult::Hit(1, udp_rule.action.clone().into());
                                }
                            }
                        }
                    }
                };

                match l5.get_app_type() {
                    // TODO: 等待后续支持 HTTP 协议
                    _ => {}
                }

                debug!(target: "SURICATA(VecSurules::detect)", "MISS current Rule!");
                DetectResult::Miss
            }

            // Warning：目前暂不支持 L3 规则
            QuinPacket::L3(_l3) => return DetectResult::Miss,

            // L1、L2 数据包直接判断为未匹配到规则
            _ => return DetectResult::Miss,
        }
    }
}
