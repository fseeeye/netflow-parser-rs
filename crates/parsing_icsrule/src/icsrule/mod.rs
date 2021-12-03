mod basis;
mod hm_rules;

pub(crate) use self::basis::Action;
pub use self::hm_rules::HmIcsRules;

use self::basis::IcsRuleBasis;
use super::icsrule_arg::IcsRuleArgs;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct IcsRule {
    #[serde(flatten)]
    pub basic: IcsRuleBasis,
    #[serde(flatten)]
    pub args: IcsRuleArgs,
}