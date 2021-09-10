mod basic_rule;
mod modbus_rule;

pub(super) use self::basic_rule::{Action, CAction};

use serde::{Deserialize, Serialize};
use super::rule_arg::RuleArgs;
use self::basic_rule::BasicRule;

#[derive(Serialize, Deserialize, Debug)]
pub struct Rule {
    #[serde(flatten)]
    pub basic: BasicRule,
    #[serde(flatten)]
    pub args: RuleArgs,
}