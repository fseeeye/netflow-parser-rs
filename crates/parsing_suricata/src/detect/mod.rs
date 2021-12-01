use parsing_parser::QuinPacket;
use parsing_rule::*;

use crate::surule::{Surule, types::Action};

impl Into<RuleAction> for Action {
    fn into(self) -> RuleAction {
        match self {
            Action::Alert => RuleAction::Alert,
            Action::Drop => RuleAction::Drop,
            Action::Pass => RuleAction::Pass,
            Action::Reject | Action::RejectBoth | Action::RejectDst | Action::RejectSrc => RuleAction::Reject
        }
    }
}

impl Rule for Surule {
    fn detect(&self, _packet: &QuinPacket) -> DetectResult {
        // TODO
        DetectResult::Hit(Action::Pass.into())
    }
}