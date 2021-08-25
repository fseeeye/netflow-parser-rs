mod modbus_rule;

use std::net::IpAddr;
use std::fs;

use crate::{QuinPacket, field_type::MacAddress};
use self::modbus_rule::ModbusRule;

use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize, Debug)]
#[serde(tag="proname")]
pub enum Rule {
    Modbus(ModbusRule)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BasicRule {
    pub rid: u32,
    pub action: Action,
    pub src_mac: Option<MacAddress>,
    pub src_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dir: Direction,
    pub dst_mac: Option<MacAddress>,
    pub dst_ip: Option<IpAddr>,
    pub dst_port: Option<u16>,
    pub msg: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Alert,
    Drop,
    Reject,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Direction {
    #[serde(rename = "->")]
    Uni,
    #[serde(rename = "<>")]
    Bi,
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

pub fn check_rule(rules: &Rules, packet: QuinPacket) -> bool {
    
    return true
}