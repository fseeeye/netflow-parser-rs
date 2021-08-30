use std::{collections::{BTreeSet, HashMap}, fs};

use crate::layer_type::ApplicationLayerNaiveType;

use super::{rule::Rule, rule_arg::RuleArgs};


/// Rules是存储规则集合的数据结构。
/// > Tips: 目前数据结构处于待完善阶段。
#[derive(Debug)]
pub struct Rules {
    pub rules_inner: HashMap<u32, Rule>,
    pub rules_map: HashMap<ApplicationLayerNaiveType, BTreeSet<u32>>,
}

impl Rules {
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
            Err(_e) => return false, 
        };

        // convert json str to vec<Rule>
        let rules_vec: Vec<Rule> = match serde_json::from_str(file_contents.as_str()) {
            Ok(o) => o,
            Err(_e) => {
                println!("{:?}", _e);
                return false
            }
        };

        // init attributes of Rules
        for rule in rules_vec {
            let rid = rule.basic.rid;
            let protocol_type = match rule.args{
                RuleArgs::Modbus(..) => ApplicationLayerNaiveType::Modbus,
            };
            (*self.rules_map.entry(protocol_type).or_insert(BTreeSet::<u32>::new())).insert(rid);
            self.rules_inner.insert(rid, rule);
        }

        return true
    }
}
