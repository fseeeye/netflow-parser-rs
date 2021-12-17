use parsing_parser::{L5Packet, QuinPacket};
use parsing_rule::*;
use tracing::debug;

use super::icsrule::{Action, HmIcsRules};

pub trait IcsRuleDetector {
    fn detect(&self, l5: &L5Packet) -> bool;
}

impl Into<RuleAction> for Action {
    fn into(self) -> RuleAction {
        match self {
            Action::Alert => RuleAction::Alert,
            Action::Allow => RuleAction::Pass,
            Action::Drop => RuleAction::Drop,
            Action::Reject => RuleAction::Reject,
        }
    }
}

impl RulesDetector for HmIcsRules {
    fn detect(&self, packet: &QuinPacket) -> DetectResult {
        // ics规则要求packet为L5，否则返回false
        if let &QuinPacket::L5(l5) = &packet {
            // Warning: demo detect code...
            // 目前还未针对 rules 的数据结构做优化，加速规则匹配过程
            for (_, rule) in &self.rules_inner {
                debug!(target: "ICSRULE(HmIcsRules::detect)", "detecting ICS rule: {:?}", rule);
                if rule.basic.detect(l5) {
                    if rule.args.detect(l5) {
                        return DetectResult::Hit(rule.basic.action.to_owned().into());
                        // Warning: extra clone?
                    }
                }
            }
        }

        DetectResult::Miss
    }
}
