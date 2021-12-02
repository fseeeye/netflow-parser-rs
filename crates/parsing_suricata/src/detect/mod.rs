use parsing_parser::QuinPacket;
use parsing_rule::*;

use crate::surule::{Surule, elements::Action};

impl Into<RuleAction> for Action {
    fn into(self) -> RuleAction {
        match self {
            Action::Alert => RuleAction::Alert,
            Action::Drop => RuleAction::Drop,
            Action::Pass => RuleAction::Pass,
            Action::Reject | Action::RejectBoth | Action::RejectDst | Action::RejectSrc => RuleAction::Reject
        }
    }
}

impl Rule for Surule {
    fn detect(&self, packet: &QuinPacket) -> DetectResult {
        // TODO

        // 判断该数据包为第几层协议
        match packet {
            QuinPacket::L3(_l3) => {},
            QuinPacket::L4(_l4) => {},
            QuinPacket::L5(_l5) => {},
            _ => return DetectResult::Miss // L1、L2 数据包直接判断为未匹配到规则
        }

        DetectResult::Hit(Action::Pass.into())
    }
}