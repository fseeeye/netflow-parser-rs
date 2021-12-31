mod basis;
mod hm_rules;

pub(crate) use self::basis::Action;
pub use self::basis::IcsRuleBasis;
pub use self::hm_rules::HmIcsRules;

use super::icsrule_arg::IcsRuleArgs;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct IcsRule {
    #[serde(flatten)]
    pub basic: IcsRuleBasis,
    #[serde(flatten)]
    pub args: IcsRuleArgs,
}
