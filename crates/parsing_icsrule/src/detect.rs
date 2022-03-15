use parsing_parser::{AppLevel, L5Packet, QuinPacket};
use parsing_rule::*;
use tracing::debug;

use super::icsrule::{basis::Action, HmIcsRules};

pub trait IcsRuleDetector {
    fn detect(&self, l5: &L5Packet) -> bool;
}

impl Into<RuleAction> for Action {
    fn into(self) -> RuleAction {
        match self {
            Action::Alert => RuleAction::Alert,
            Action::Pass => RuleAction::Pass,
            Action::Drop => RuleAction::Drop,
            Action::Reject => RuleAction::Reject,
        }
    }
}

impl RulesDetector for HmIcsRules {
    fn detect(&self, packet: &QuinPacket) -> DetectResult {
        // ics规则要求packet为L5，否则返回false
        if let &QuinPacket::L5(l5) = &packet {
            let app_native_type = l5.get_app_naive_type();
            if let Some(vec_rid) = self.rules_map.get(&app_native_type) {
                for rid in vec_rid {
                    if let Some(rule) = self.rules_inner.get(rid) {
                        if rule.basic.active {
                            debug!(target: "ICSRULE(HmIcsRules::detect)", "detecting ICS rule: {:?}", rule);
                            if rule.basic.detect(l5) {
                                if rule.args.detect(l5) {
                                    return DetectResult::Hit(
                                        rule.basic.rid,
                                        rule.basic.action.to_owned().into(),
                                    );
                                    // Warning: extra clone?
                                }
                            }
                        }
                    } else {
                        continue;
                    };
                }
            }
        }

        DetectResult::Miss
    }
}
