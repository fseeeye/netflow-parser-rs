use parsing_parser::{LinkProtocol, NetworkProtocol, ApplicationNaiveProtocol, TransportProtocol};
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

// 返回防火墙 protocol id
pub trait AdaptProtocolId {
    fn get_firewall_protocol_id(&self) -> u8;
}

impl AdaptProtocolId for LinkProtocol {
    fn get_firewall_protocol_id(&self) -> u8 {
        match self {
            LinkProtocol::Ethernet => 1
        }
    }
}

impl AdaptProtocolId for NetworkProtocol {
    fn get_firewall_protocol_id(&self) -> u8 {
        match self {
            NetworkProtocol::Ipv4  => 3,
            NetworkProtocol::Ipv6  => 4,
            NetworkProtocol::Goose => 26,
            NetworkProtocol::Vlan  => 41,
        }
    }
}

impl AdaptProtocolId for TransportProtocol {
    fn get_firewall_protocol_id(&self) -> u8 {
        match self {
            TransportProtocol::Tcp => 5,
            TransportProtocol::Udp => 6,
            TransportProtocol::Sv  => 25
        }
    }
}

impl AdaptProtocolId for ApplicationNaiveProtocol {
    fn get_firewall_protocol_id(&self) -> u8 {
        match self {
            ApplicationNaiveProtocol::Bacnet   => 34,
            ApplicationNaiveProtocol::Dnp3     => 24,
            ApplicationNaiveProtocol::Fins     => 28,
            ApplicationNaiveProtocol::Http     => 14,
            ApplicationNaiveProtocol::Iec104   => 27,
            ApplicationNaiveProtocol::IsoOnTcp => 20,
            ApplicationNaiveProtocol::Mms      => 42,
            ApplicationNaiveProtocol::Modbus   => 22,
            ApplicationNaiveProtocol::Opcua    => 31,
            ApplicationNaiveProtocol::S7comm   => 23
        }
    }
}
