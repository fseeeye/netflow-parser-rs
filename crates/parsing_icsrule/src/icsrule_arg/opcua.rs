use parsing_parser::{parsers::opcua, ApplicationLayer, L5Packet};
use serde::{Deserialize, Serialize};

use crate::{detect::IcsRuleDetector, detect_option_eq};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct OpcuaArg {
    #[serde(rename = "type")]
    message_type: Option<u32>,
    #[serde(rename = "function_code")]
    service_nodeid_numeric: Option<u32>,
}

impl IcsRuleDetector for OpcuaArg {
    fn detect(&self, l5: &L5Packet) -> bool {
        if let ApplicationLayer::Opcua(opcua) = &l5.application_layer {
            detect_option_eq!(self.message_type, opcua.message_type);

            if let Some(target_service_nodeid_numeric) = self.service_nodeid_numeric {
                if let opcua::MessageTypeEnum::Message {
                    msg_variant_info:
                        opcua::MsgVariantInfo::Service {
                            service_nodeid_info,
                            ..
                        },
                    ..
                } = &opcua.message_type_enum
                {
                    match service_nodeid_info {
                        opcua::ServiceNodeidInfo::TB {
                            service_nodeid_numeric,
                            ..
                        } => {
                            if target_service_nodeid_numeric != *service_nodeid_numeric as u32 {
                                return false;
                            }
                        }
                        opcua::ServiceNodeidInfo::FB {
                            service_nodeid_numeric,
                            ..
                        } => {
                            if target_service_nodeid_numeric != *service_nodeid_numeric as u32 {
                                return false;
                            }
                        }
                        opcua::ServiceNodeidInfo::Numeric {
                            service_nodeid_numeric,
                            ..
                        } => {
                            if target_service_nodeid_numeric != *service_nodeid_numeric {
                                return false;
                            }
                        }
                        _ => return false,
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
    use crate::{
        icsrule::basis::{Action, Direction},
        icsrule_arg::IcsRuleArg,
        HmIcsRules, IcsRule, IcsRuleBasis,
    };

    use super::*;

    #[test]
    fn serialize_opcua_icsrule() {
        let opcua_rule = IcsRule {
            basic: IcsRuleBasis {
                active: true,
                rid: 1,
                action: Action::Alert,
                src_ip: None,
                src_port: None,
                dir: Direction::Uni,
                dst_ip: None,
                dst_port: Some(9600),
                msg: "Opcua Read".to_string(),
            },
            args: IcsRuleArg::OPCUA(OpcuaArg {
                message_type: Some(0x04),
                service_nodeid_numeric: Some(631),
            }),
        };

        assert_eq!(
            serde_json::to_string(&opcua_rule).unwrap(),
            r#"{"active":true,"rid":1,"action":"alert","src":null,"sport":null,"dire":"->","dst":null,"dport":9600,"msg":"Opcua Read","proname":"OPCUA","args":{"type":4,"function_code":631}}"#
        )
    }

    #[test]
    fn deserialize_dnp3_icsrule() {
        let mut fins_rule = HmIcsRules::new();

        let file_str = "./tests/unitest_opcua.json";
        assert!(fins_rule.load_rules(file_str));
    }
}
