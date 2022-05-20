use parsing_parser::{parsers::mms::MmsPduEnum, ApplicationLayer, L5Packet};
use serde::{Deserialize, Serialize};

use crate::detect::IcsRuleDetector;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct MmsArg {
    tag: MmsTag
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum MmsTag {
    #[serde(rename = "0x00", alias = "0")]
    ConfirmedRequestPDU,
    #[serde(rename = "0x01", alias = "1")]
    ConfirmedResponsePDU,
    #[serde(rename = "0x03", alias = "3")]
    UnConfirmedPDU,
    #[serde(rename = "0x08", alias = "8")]
    InitiateRequestPDU,
    #[serde(rename = "0x09", alias = "9")]
    InitiateResponsePDU,
    #[serde(rename = "0x0b", alias = "11")]
    ConcludeRequest
}

impl IcsRuleDetector for MmsArg {
    fn detect(&self, l5: &L5Packet) -> bool {
        if let ApplicationLayer::Mms(mms) = &l5.application_layer {
            match mms.mms_pdu.mms_pdu_enum {
                MmsPduEnum::ConcludeRequest { } => {
                    if self.tag != MmsTag::ConcludeRequest {
                        return false;    
                    }
                }
                MmsPduEnum::ConfirmedRequestPDU { .. } => {
                    if self.tag != MmsTag::ConfirmedRequestPDU {
                        return false;    
                    }
                }
                MmsPduEnum::ConfirmedResponsePDU { .. } => {
                    if self.tag != MmsTag::ConfirmedResponsePDU {
                        return false;    
                    }
                }
                MmsPduEnum::InitiateRequestPDU { .. } => {
                    if self.tag != MmsTag::InitiateRequestPDU {
                        return false;    
                    }
                }
                MmsPduEnum::InitiateResponsePDU { .. } => {
                    if self.tag != MmsTag::InitiateResponsePDU {
                        return false;    
                    }
                }
                MmsPduEnum::UnConfirmedPDU { .. } => {
                    if self.tag != MmsTag::UnConfirmedPDU {
                        return false;    
                    }
                }
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
    fn serialize_mms_icsrule() {
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
            args: IcsRuleArg::MMS(MmsArg {
                tag: MmsTag::ConfirmedRequestPDU
            }),
        };

        assert_eq!(
            serde_json::to_string(&bacnet_rule).unwrap(),
            r#"{"active":true,"rid":1,"action":"alert","src":null,"sport":null,"dire":"->","dst":null,"dport":[20000],"msg":"MMS ConfirmedRequestPDU","proname":"MMS","args":{"tag":"0x00"}}"#
        )
    }

    #[test]
    fn deserialize_mms_icsrule() {
        let mut mms_rule = HmIcsRules::new();

        let file_str = "./tests/unitest_mms.json";
        assert!(mms_rule.load_rules(file_str));
    }
}
