use parsing_parser::ApplicationNaiveProtocol;
use tracing::error;

use std::{
    collections::{BTreeSet, HashMap},
    fs,
};

use super::{IcsRule, IcsRuleArgs};

/// HmIcsRules是存储规则集合的数据结构，它采用 HashMap 来存取所有规则。
/// > Tips: 目前数据结构处于待完善阶段。
#[derive(Debug)]
pub struct HmIcsRules {
    pub rules_inner: HashMap<u32, IcsRule>,
    pub rules_map: HashMap<ApplicationNaiveProtocol, BTreeSet<u32>>,
}

impl HmIcsRules {
    pub fn new() -> Self {
        let rules_inner = HashMap::new();
        let rules_map = HashMap::new();
        Self {
            rules_inner,
            rules_map,
        }
    }

    pub fn init(&mut self, rule_file_path: &str) -> bool {
        // read file from sys
        let file_contents = match fs::read_to_string(rule_file_path) {
            Ok(o) => o,
            Err(e) => {
                error!(target: "ICSRULE(HmIcsRules::init)", error = ?e, "occur error while reading rule string.");
                return false
            },
        };

        // convert json str to vec<Rule>
        let rules_vec: Vec<IcsRule> = match serde_json::from_str(file_contents.as_str()) {
            Ok(o) => o,
            Err(e) => {
                error!(target: "ICSRULE(HmIcsRules::init)", error = ?e, "occur error while serding rule string.");
                return false;
            }
        };

        // init attributes of Rules
        for rule in rules_vec {
            let rid = rule.basic.rid;
            let protocol_type = match rule.args {
                IcsRuleArgs::Modbus(..) => ApplicationNaiveProtocol::Modbus,
            };
            (*self
                .rules_map
                .entry(protocol_type)
                .or_insert(BTreeSet::<u32>::new()))
            .insert(rid);
            self.rules_inner.insert(rid, rule);
        }

        return true;
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, str::FromStr};

    use crate::{IcsRuleBasis, icsrule::{Action, basis::Direction}, icsrule_arg::{ModbusArg, ModbusReqArg, ModbusRspArg}};

    use super::*;

    #[test]
    fn parse_ics_rules() {
        let file_str = "./tests/unitest_ics_rules.json";
        let mut ics_rules = HmIcsRules::new();
        assert!(ics_rules.init(file_str));
        
        let mut rule_iter = ics_rules.rules_inner.iter();
        if let Some((_, ics_rule)) = rule_iter.next() {
            assert_eq!(
                *ics_rule,
                IcsRule {
                    basic: IcsRuleBasis {
                        rid: 1,
                        action: Action::Drop,
                        src_ip: Some(IpAddr::from_str("192.168.3.189").unwrap()),
                        src_port: None,
                        dir: Direction::Bi,
                        dst_ip: None,
                        dst_port: None,
                        msg: "Modbus: Read Discrete Inputs(2)".to_string(),
                    },
                    args: IcsRuleArgs::Modbus(vec![
                        ModbusArg::ModbusReq(ModbusReqArg {
                            mbap_header: Some(crate::icsrule_arg::modbus_req::MbapHeader {
                                transaction_id: None,
                                protocol_id: None,
                                length: None,
                                unit_id: None,
                            }),
                            pdu: Some(crate::icsrule_arg::modbus_req::PDU {
                                data: Some(crate::icsrule_arg::modbus_req::Data::ReadDiscreteInputs {
                                    start_address: None,
                                    count: None
                                })
                            })
                        }),
                        ModbusArg::ModbusRsp(ModbusRspArg {
                            mbap_header: Some(crate::icsrule_arg::modbus_rsp::MbapHeader {
                                transaction_id: Some(256),
                                protocol_id: Some(0),
                                length: Some(4),
                                unit_id: Some(1),
                            }),
                            pdu: Some(crate::icsrule_arg::modbus_rsp::PDU {
                                data: Some(crate::icsrule_arg::modbus_rsp::Data::ReadDiscreteInputs {
                                    byte_count: Some(1)
                                })
                            })
                        })
                    ])
                }
            );
        } else {
            assert!(false);
        }
    }
}