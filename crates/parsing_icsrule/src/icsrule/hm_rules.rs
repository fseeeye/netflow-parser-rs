use parsing_parser::ApplicationNaiveProtocol;

use std::{
    collections::HashMap,
    fs,
};

use super::IcsRule;

/// HmIcsRules是存储规则集合的数据结构，它采用 HashMap 来存取所有规则。
/// > Tips: 目前数据结构处于待完善阶段。
#[derive(Debug)]
pub struct HmIcsRules {
    pub rules_inner: HashMap<usize, IcsRule>,
    pub rules_map: HashMap<ApplicationNaiveProtocol, Vec<usize>>,
}

impl HmIcsRules {
    
    pub fn new() -> Self {
        Self {
            rules_inner: HashMap::new(),
            rules_map: HashMap::new()
        }
    }

    pub fn load_rules(&mut self, rule_file_path: &str) -> bool {
        // read file from sys
        let file_contents = match fs::read_to_string(rule_file_path) {
            Ok(o) => o,
            Err(e) => {
                tracing::error!(error = ?e, "error occurs while reading rule string.");
                return false;
            }
        };

        // convert json str to vec<Rule>
        let rules_vec: Vec<IcsRule> = match serde_json::from_str(file_contents.as_str()) {
            Ok(o) => o,
            Err(e) => {
                tracing::error!(error = ?e, "error occurs while serding rule string.");
                return false;
            }
        };

        // insert Rules
        for rule in rules_vec {
            let rid = rule.basic.rid;
            let protocol_type = rule.get_protocol_type();

            self.rules_map
                .entry(protocol_type)
                .or_insert(Vec::<usize>::new())
                .push(rid);
            
            self.rules_inner.insert(rid, rule);
        }

        return true;
    }

    pub fn delete_rule(&mut self, rule_rid: usize) {
        // remove rid in rules map
        for (_protocol, rids_vec) in &mut self.rules_map {
            if let Some(index) = rids_vec.iter().position(|x| *x == rule_rid) {
                rids_vec.remove(index);
            }
        }

        // remove rule in inner rules
        self.rules_inner.remove(&rule_rid);
    }

    pub fn active_rule(&mut self, rule_rid: usize) {
        if let Some(target_rule) = self.rules_inner.get_mut(&rule_rid) {
            target_rule.basic.active = true;
        }
    }

    pub fn deactive_rule(&mut self, rule_rid: usize) {
        if let Some(target_rule) = self.rules_inner.get_mut(&rule_rid) {
            target_rule.basic.active = false;
        }
    }

}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, str::FromStr};

    use crate::{
        icsrule::basis::{Direction, Action},
        icsrule_arg::{ModbusArg, IcsRuleArg},
        IcsRuleBasis,
    };

    use super::*;

    fn load_modbus_icsrule() -> HmIcsRules {
        let mut ics_rules = HmIcsRules::new();
        let file_str = "./tests/unitest_modbus.json";
        ics_rules.load_rules(file_str);

        return ics_rules;
    }

    #[test]
    fn load_unitest_icsrule() {
        let mut ics_rules = HmIcsRules::new();
        let file_strs = vec![
            "./tests/unitest_modbus.json",
            "./tests/unitest_s7comm.json"
        ];
        for file_str in file_strs {
            assert!(ics_rules.load_rules(file_str));
        }
    }

    #[test]
    fn parse_icsrules() {
        let ics_rules = load_modbus_icsrule();

        if let Some(ics_rule) = ics_rules.rules_inner.get(&1) {
            assert_eq!(
                *ics_rule,
                IcsRule {
                    basic: IcsRuleBasis {
                        active: true,
                        rid: 1,
                        action: Action::Alert,
                        src_ip: Some(IpAddr::from_str("192.168.3.189").unwrap()),
                        src_port: None,
                        dir: Direction::Uni,
                        dst_ip: None,
                        dst_port: Some(502),
                        msg: "Modbus Read Coils(1)".to_string(),
                    },
                    args: IcsRuleArg::Modbus(
                        ModbusArg::ReadCoils {
                            start_address: Some(0),
                            end_address: Some(10)
                        }
                    )
                }
            );
        } else {
            assert!(false);
        }
    }

    #[test]
    fn delete_icsrule() {
        let mut ics_rules = load_modbus_icsrule();

        ics_rules.delete_rule(1);
        
        // println!("rules_map: {:?}", ics_rules.rules_map);
        // println!("rules_inner: {:?}", ics_rules.rules_inner);
        for (_k, v) in &ics_rules.rules_map {
            assert!(v.is_empty());
        }
        assert!(ics_rules.rules_inner.is_empty());
    }

    #[test]
    fn deactive_icsrule() {
        let mut ics_rules = load_modbus_icsrule();

        ics_rules.deactive_rule(1);
        assert!(ics_rules.rules_inner.get(&1).unwrap().basic.active == false);
        ics_rules.active_rule(1);
        assert!(ics_rules.rules_inner.get(&1).unwrap().basic.active == true);
    }
}
