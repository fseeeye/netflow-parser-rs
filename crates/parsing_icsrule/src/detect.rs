use parsing_parser::{AppLevel, L5Packet, QuinPacket};
use parsing_rule::*;
use tracing::debug;

use super::icsrule::HmIcsRules;

pub trait IcsRuleDetector {
    fn detect(&self, l5: &L5Packet) -> bool;
}

impl RulesDetectorICS for HmIcsRules {
    fn detect(&self, packet: &QuinPacket) -> DetectResultICS {
        let mut is_detected_basic = false;

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
                                    return DetectResultICS::Hit(
                                        rule.basic.rid,
                                        rule.basic.action.clone(),
                                    );
                                    // Warning: extra clone?
                                } else {
                                    // will trigger Content Warning
                                    if !is_detected_basic {
                                        is_detected_basic = true;
                                    }
                                }
                            }
                        }
                    } else {
                        continue;
                    };
                }
            }
        }

        if is_detected_basic {
            DetectResultICS::Miss(DetectMiss::Content)
        } else {
            DetectResultICS::Miss(DetectMiss::Behavior)
        }
    }
}
