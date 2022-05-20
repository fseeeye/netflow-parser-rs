use parsing_parser::{parsers::bacnet, ApplicationLayer, L5Packet};
use serde::{Deserialize, Serialize};

use crate::{detect::IcsRuleDetector, detect_option_eq};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct BacnetArg {
    #[serde(rename = "type")]
    apdu_type: Option<u8>,
    service_choice: Option<u8>,
}

impl IcsRuleDetector for BacnetArg {
    fn detect(&self, l5: &L5Packet) -> bool {
        if let ApplicationLayer::Bacnet(bacnet) = &l5.application_layer {
            match &bacnet.apdu_option {
                bacnet::ApduOption::Apdu { apdu_type, ref apdu_info, .. } => {
                    detect_option_eq!(self.apdu_type, *apdu_type);
                    
                    match apdu_info {
                        &bacnet::ApduInfo::ComplexAckPdu { service_choice, .. } => {
                            detect_option_eq!(self.service_choice, service_choice);
                        }
                        &bacnet::ApduInfo::ComfirmedServiceRequest { service_choice, .. } => {
                            detect_option_eq!(self.service_choice, service_choice);
                        }
                    }
                }
                _ => return false
            }
            
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
    fn serialize_bacnet_icsrule() {
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
                msg: "BACnet ReadProperty".to_string(),
            },
            args: IcsRuleArg::BACNET(BacnetArg {
                apdu_type: Some(1),
                service_choice: Some(2)
            }),
        };

        assert_eq!(
            serde_json::to_string(&bacnet_rule).unwrap(),
            r#"{"active":true,"rid":1,"action":"alert","src":null,"sport":null,"dire":"->","dst":null,"dport":[20000],"msg":"BACnet ReadProperty","proname":"BACNET","args":{"type":1,"service_choice":2}}"#
        )
    }

    #[test]
    fn deserialize_bacnet_icsrule() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .init();

        let mut bacnet_rule = HmIcsRules::new();

        let file_str = "./tests/unitest_bacnet.json";
        assert!(bacnet_rule.load_rules(file_str));
    }
}
