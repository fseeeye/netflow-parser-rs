use serde::{Serialize, Deserialize};

use crate::ics_rule::rule_arg::ModbusArg;
use super::BasicRule;

#[derive(Serialize, Deserialize, Debug)]
pub struct ModbusRule {
    #[serde(flatten)]
    pub basic: BasicRule,
    pub args: Option<Vec<ModbusArg>>,
}