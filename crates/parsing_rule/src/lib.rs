use parsing_parser::QuinPacket;

#[derive(Debug, Clone, PartialEq)]
pub enum RuleAction {
    Alert,
    Drop,
    Reject,
    Pass,
}

#[derive(Debug)]
pub enum DetectResult {
    Hit(RuleAction),
    Miss,
}

pub trait Rules {
    fn detect(&self, packet: &QuinPacket) -> DetectResult;
}
