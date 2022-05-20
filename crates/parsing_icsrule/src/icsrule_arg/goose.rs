use parsing_parser::{ApplicationLayer, L5Packet};
use serde::{Deserialize, Serialize};

use crate::{detect::IcsRuleDetector, detect_option_eq};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct GooseArg {
    appid: Option<u16>
}

impl IcsRuleDetector for GooseArg {
    fn detect(&self, l5: &L5Packet) -> bool {
        if let ApplicationLayer::Goose(goose) = &l5.application_layer {
            detect_option_eq!(self.appid, goose.appid);

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
    fn serialize_goose_icsrule() {
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
                msg: "GOOSE".to_string(),
            },
            args: IcsRuleArg::GOOSE(GooseArg {
                appid: Some(1)
            }),
        };

        assert_eq!(
            serde_json::to_string(&bacnet_rule).unwrap(),
            r#"{"active":true,"rid":1,"action":"alert","src":null,"sport":null,"dire":"->","dst":null,"dport":[20000],"msg":"GOOSE","proname":"GOOSE","args":{"appid":1}}"#
        )
    }

    #[test]
    fn deserialize_goose_icsrule() {
        let mut goose_rule = HmIcsRules::new();

        let file_str = "./tests/unitest_goose.json";
        assert!(goose_rule.load_rules(file_str));
    }
}
