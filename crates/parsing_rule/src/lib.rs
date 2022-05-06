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

// Detect Result for ICS Rule
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub enum DetectResultICS {
    Hit(usize, RuleAction),
    Miss(DetectMiss),
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub enum DetectMiss {
    Behavior,
    Content
}

// Detect Trait
pub trait RulesDetector {
    fn detect(&self, packet: &QuinPacket) -> DetectResult;
}

pub trait RulesDetectorICS {
    fn detect(&self, packet: &QuinPacket) -> DetectResultICS;
}
