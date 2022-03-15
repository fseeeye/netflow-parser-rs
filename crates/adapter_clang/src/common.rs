use parsing_rule::RuleAction;

/// 启用日志输出
#[no_mangle]
pub extern "C" fn enable_tracing_rs() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .init();
}

#[allow(dead_code)]
pub fn rule_action_to_firewall_action(rule_action: RuleAction) -> u8 {
    match rule_action {
        RuleAction::Alert => 1,
        RuleAction::Drop => 2,
        RuleAction::Reject => 3,
        RuleAction::Pass => 4,
    }
}

#[allow(dead_code)]
pub fn rule_action_to_ids_action(rule_action: RuleAction) -> u8 {
    match rule_action {
        RuleAction::Alert => 0x01,
        RuleAction::Drop => 0x02,
        RuleAction::Reject => 0x04,
        RuleAction::Pass => 0x20,
    }
}
