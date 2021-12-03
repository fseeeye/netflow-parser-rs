use parsing_parser::{QuinPacket, TransLevel, TransportProtocol, AppLevel};
use parsing_rule::*;

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

impl Rules for VecSurules {
    fn detect(&self, packet: &QuinPacket) -> DetectResult {
        // Warning: 目前数据包规则匹配过程中，直接返回第一个匹配到的规则的 Action，无法设置单个规则优先级。

        // 判断该数据包为第几层协议
        match packet {
            QuinPacket::L4(l4) => {
                match l4.get_tran_type() {
                    TransportProtocol::Tcp => {
                        // detect tcp suricata rules for this packet
                        // TODO
                        DetectResult::Hit(Action::Pass.into())
                    },
                    TransportProtocol::Udp => {
                        // detect udp suricata rules for this packet
                        // TODO
                        DetectResult::Hit(Action::Pass.into())
                    }
                }
            }
            QuinPacket::L5(l5) => {
                // Warning: 传输层规则 tcp / udp 优先级高于
                let result = match l5.get_tran_type() {
                    TransportProtocol::Tcp => {
                        // detect tcp suricata rules for this packet
                        // TODO
                        DetectResult::Hit(Action::Pass.into())
                    },
                    TransportProtocol::Udp => {
                        // detect udp suricata rules for this packet
                        // TODO
                        DetectResult::Hit(Action::Pass.into())
                    }
                };

                if let DetectResult::Miss = result {
                    match l5.get_app_type() {
                        // TODO: 等待后续支持 HTTP 协议
                        _ => {
                            DetectResult::Miss
                        }
                    }
                } else {
                    result
                }
            }
            // Warning：目前暂不支持 L3 规则
            QuinPacket::L3(_l3) => return DetectResult::Miss,
            // L1、L2 数据包直接判断为未匹配到规则
            _ => return DetectResult::Miss,
        }
    }
}
