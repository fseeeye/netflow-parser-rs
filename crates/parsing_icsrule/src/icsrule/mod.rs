pub(crate) mod basis;
pub(crate) mod hm_rules;

pub use self::basis::IcsRuleBasis;
pub use self::hm_rules::HmIcsRules;

use super::icsrule_arg::IcsRuleArg;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct IcsRule {
    #[serde(flatten)]
    pub basic: IcsRuleBasis,
    #[serde(flatten)]
    pub args: IcsRuleArg,
}
