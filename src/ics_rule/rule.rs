mod basic_rule;
mod modbus_rule;

use std::fs;

use crate::{QuinPacket, RuleTrait};
use self::modbus_rule::ModbusRule;

use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize, Debug)]
#[serde(tag="proname")]
pub enum Rule {
    Modbus(ModbusRule)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Rules {
    pub inner_rules: Vec<Rule>
}

impl Rules {
    pub fn new() -> Self {
        let inner_rules: Vec<Rule> = Vec::new();
        Self {
            inner_rules
        }
    }
}

pub fn init_whitelist_rules(rules: &mut Rules, file_str: &str) -> bool {
    // read file from sys
    let file_contents = match fs::read_to_string(file_str) {
        Ok(o) => o,
        Err(_e) => return false, 
    };

    // convert json str to vec rules
    let inner_rules: Vec<Rule> = match serde_json::from_str(file_contents.as_str()) {
        Ok(o) => o,
        Err(_e) => {
            println!("{:?}", _e);
            return false
        }
    };

    rules.inner_rules = inner_rules;

    return true
}

pub fn check_ics_rule(rules: &Rules, packet: &QuinPacket) -> bool {
    // ics规则要求packet为L5，否则返回false
    if let &QuinPacket::L5(l5) = &packet {
        for rule in &rules.inner_rules {
            match rule {
                Rule::Modbus(modbus_rule) => {
                    if modbus_rule.check_rule(l5) {
                        return true;
                    }
                },
                // ...
            };   
        }
    }

    false
}