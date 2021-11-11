use parsing_parser::{QuinPacket, L5Packet};
use super::rule::{Action, Rules};


pub trait RuleDetector {
    fn detect(&self, l5: &L5Packet) -> bool;
}

#[derive(Debug)]
pub enum CheckResult {
    Miss,
    Hit(Action),
}

pub fn detect_ics(rules: &Rules, packet: &QuinPacket) -> CheckResult {
    // ics规则要求packet为L5，否则返回false
    if let &QuinPacket::L5(l5) = &packet {
        // Warning: demo detect code...
        for (_, rule) in &rules.rules_inner {
            if !rule.basic.detect(l5) {
                continue
            }
            if rule.args.detect(l5) {
                return CheckResult::Hit(rule.basic.action)
            }
        }
    }

    CheckResult::Miss
}