use parsing_parser::QuinPacket;

#[derive(Debug, Clone, PartialEq)]
pub enum RuleAction {
    Alert,
    Drop,
    Reject,
    Pass,
}

#[derive(Debug, PartialEq)]
pub enum DetectResult {
    Hit(RuleAction),
    Miss,
}

pub trait RulesDetector {
    fn detect(&self, packet: &QuinPacket) -> DetectResult;
}
