pub(crate) mod basis;
pub(crate) mod hm_rules;

pub use self::basis::IcsRuleBasis;
pub use self::hm_rules::HmIcsRules;

use super::icsrule_arg::IcsRuleArg;
use parsing_parser::ApplicationNaiveProtocol;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct IcsRule {
    #[serde(flatten)]
    pub basic: IcsRuleBasis,
    #[serde(flatten)]
    pub args: IcsRuleArg,
}

impl IcsRule {
    pub fn get_protocol_type(&self) -> ApplicationNaiveProtocol {
        match self.args {
            IcsRuleArg::Modbus(..) => ApplicationNaiveProtocol::Modbus,
            IcsRuleArg::S7COMM(..) => ApplicationNaiveProtocol::S7comm,
            IcsRuleArg::DNP3(..) => ApplicationNaiveProtocol::Dnp3,
            IcsRuleArg::FINS(..) => ApplicationNaiveProtocol::Fins,
            IcsRuleArg::OPCUA(..) => ApplicationNaiveProtocol::Opcua,
        }
    }
}
