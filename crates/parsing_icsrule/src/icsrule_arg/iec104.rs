use parsing_parser::{parsers::iec104, ApplicationLayer, L5Packet};
use serde::{Deserialize, Serialize};

use crate::{detect::IcsRuleDetector, detect_option_eq};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct IEC104Arg {
    #[serde(flatten)]
    apdu_type: IEC104TypeEnum
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "type")]
pub enum IEC104TypeEnum {
    U {
        utype: Option<u8>
    },
    I,
    S
}

impl IcsRuleDetector for IEC104Arg {
    fn detect(&self, l5: &L5Packet) -> bool {
        if let ApplicationLayer::Iec104(iec104) = &l5.application_layer {
            if iec104.iec104_blocks.len() > 0 {
                match iec104.iec104_blocks[0].type_block {
                    iec104::TypeBlock::TypeI { .. } => {
                        if self.apdu_type != IEC104TypeEnum::I { 
                            return false
                        }
                    }
                    iec104::TypeBlock::TypeS { .. } => {
                        if self.apdu_type != IEC104TypeEnum::S { 
                            return false
                        }
                    }
                    iec104::TypeBlock::TypeU { apci_utype, .. } => {
                        if let IEC104TypeEnum::U { utype } = self.apdu_type {
                            detect_option_eq!(utype, apci_utype);
                        } else {
                            return false
                        }
                    }
                }

                true
            } else {
                false
            }
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
    fn serialize_iec104_icsrule() {
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
                msg: "MMS ConfirmedRequestPDU".to_string(),
            },
            args: IcsRuleArg::IEC104(IEC104Arg {
                apdu_type: IEC104TypeEnum::U { utype: Some(1) }
            }),
        };

        assert_eq!(
            serde_json::to_string(&bacnet_rule).unwrap(),
            r#"{"active":true,"rid":1,"action":"alert","src":null,"sport":null,"dire":"->","dst":null,"dport":[20000],"msg":"MMS ConfirmedRequestPDU","proname":"IEC104","args":{"type":"U","utype":1}}"#
        )
    }

    #[test]
    fn deserialize_iec104_icsrule() {
        let mut iec104_rule = HmIcsRules::new();

        let file_str = "./tests/unitest_iec104.json";
        assert!(iec104_rule.load_rules(file_str));
    }
}
