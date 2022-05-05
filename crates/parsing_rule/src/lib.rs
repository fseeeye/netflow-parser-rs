use serde::{Deserialize, Serialize};

use parsing_parser::QuinPacket;

// Action
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[derive(Debug, Clone, PartialEq)]
pub enum RuleAction {
    Alert,
    Drop,
    Reject,
    Pass,
}

// Direction
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub enum Direction {
    #[serde(rename = "->")]
    Uni,
    #[serde(rename = "<>")]
    Bi,
}

// Detect Result
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub enum DetectResult {
    Hit(usize, RuleAction),
    Miss,
}

// Detect Trait
pub trait RulesDetector {
    fn detect(&self, packet: &QuinPacket) -> DetectResult;
}
