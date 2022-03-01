use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct S7CommArg {
    rosctr: u8,
    #[serde(flatten)]
    parm: S7Parameter
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "function_code")]
pub enum S7Parameter {
    #[serde(rename = "4", alias = "0x04")]
    ReadVar {
        area: Option<u8>,
        start_address: Option<u32>,
        end_address: Option<u32>
    }
}

#[cfg(test)]
pub mod tests {
    use crate::{IcsRule, IcsRuleBasis, icsrule::basis::{Action, Direction}, icsrule_arg::IcsRuleArg};

    use super::*;

    #[test]
    fn serialize_s7comm_icsrule() {
        let s7comm_rule = IcsRule {
            basic: IcsRuleBasis {
                active: true,
                rid: 1,
                action: Action::Alert,
                src_ip: None,
                src_port: None,
                dir: Direction::Bi,
                dst_ip: None,
                dst_port: None,
                msg: "Job - Read Var (0x04)".to_string(),
            },
            args: IcsRuleArg::S7Comm(
                S7CommArg {
                    rosctr: 1,
                    parm: S7Parameter::ReadVar {
                        area: Some(1),
                        start_address: Some(1),
                        end_address: Some(1)
                    }
                }
            )
        };

        assert_eq!( 
            serde_json::to_string(&s7comm_rule).unwrap(),
            r#"{"active":true,"rid":1,"action":"alert","src":null,"sport":null,"dire":"<>","dst":null,"dport":null,"msg":"Job - Read Var (0x04)","proname":"S7Comm","args":{"rosctr":1,"function_code":"4","area":1,"start_address":1,"end_address":1}}"#
        )
    }
}