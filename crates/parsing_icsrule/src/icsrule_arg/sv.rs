use parsing_parser::{ApplicationLayer, L5Packet};
use serde::{Deserialize, Serialize};

use crate::{detect::IcsRuleDetector, detect_option_eq};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct SvArg {
    appid: Option<u16>
}

impl IcsRuleDetector for SvArg {
    fn detect(&self, l5: &L5Packet) -> bool {
        if let ApplicationLayer::Sv(sv) = &l5.application_layer {
            detect_option_eq!(self.appid, sv.appid);

            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use parsing_rule::{RuleAction, Direction};

    use crate::{
        icsrule_arg::IcsRuleArg,
        HmIcsRules, IcsRule, IcsRuleBasis, rule_utils::*,
    };

    use super::*;

    #[test]
    fn serialize_sv_icsrule() {
        let bacnet_rule = IcsRule {
            basic: IcsRuleBasis {
                active: true,
                rid: 1,
                action: RuleAction::Alert,
                src_ip: None,
                src_port: None,
                dir: Direction::Uni,
                dst_ip: None,
                dst_port: Some(NumVec(vec![Num::Single(20000u16)])),
                msg: "SV".to_string(),
            },
            args: IcsRuleArg::SV(SvArg {
                appid: Some(1)
            }),
        };

        assert_eq!(
            serde_json::to_string(&bacnet_rule).unwrap(),
            r#"{"active":true,"rid":1,"action":"alert","src":null,"sport":null,"dire":"->","dst":null,"dport":[20000],"msg":"SV","proname":"SV","args":{"appid":1}}"#
        )
    }

    #[test]
    fn deserialize_sv_icsrule() {
        let mut sv_rule = HmIcsRules::new();

        let file_str = "./tests/unitest_sv.json";
        assert!(sv_rule.load_rules(file_str));
    }
}
