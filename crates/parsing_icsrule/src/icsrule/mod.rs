mod basis;
mod hm_rules;

pub(crate) use self::basis::Action;
pub use self::hm_rules::HmIcsRules;


use serde::{Deserialize, Serialize};
use super::icsrule_arg::IcsRuleArgs;
use self::basis::IcsRuleBasis;

#[derive(Serialize, Deserialize, Debug)]
pub struct IcsRule {
    #[serde(flatten)]
    pub basic: IcsRuleBasis,
    #[serde(flatten)]
    pub args: IcsRuleArgs,
}