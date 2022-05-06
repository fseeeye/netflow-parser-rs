//! Parsing-rs是流量解析引擎，致力于高效解析和安全稳定。
//!
//! ## Example
//! ```
//! use parsing_rs::prelude::*;
//!
//! let input = &[1,2,3,4,5,6];
//! match QuinPacket::parse_from_stream(input, &QuinPacketOptions::default()) {
//!     QuinPacket::L1(l1) => {
//!         println!("l1 packet: {:?}", l1);
//!     }
//!     QuinPacket::L2(l2) => {
//!         println!("l2 packet: {:?}", l2);
//!     }
//!     QuinPacket::L3(l3) => {
//!         println!("l3 packet: {:?}", l3);
//!     }
//!     QuinPacket::L4(l4) => {
//!         println!("l4 packet: {:?}", l4);
//!     }
//!     QuinPacket::L5(l5) => {
//!         println!("l5 packet: {:?}", l5);
//!     }
//! };
//! ```
//! 这仅仅是一个分级五元组Packet结构，我们将会支持更多种类数据结构的Packet解析结果以支持多元化使用场景。
pub mod rule {
    pub use parsing_rule::*;
}

pub mod parser {
    pub use parsing_parser::*;
}

pub mod ics_rule {
    pub use parsing_icsrule::*;
}

pub mod suricata_rule {
    pub use parsing_suricata::*;
}

pub mod prelude {
    pub use crate::parser::{
        // trait
        LinkLevel,
        NetLevel,
        // structures
        QuinPacket,
        QuinPacketOptions,
        TransLevel,
    };

    pub use crate::ics_rule::HmIcsRules;

    pub use crate::rule::{
        // structures
        DetectResult,
        DetectResultICS,
        RuleAction,
        // traits
        RulesDetector,
        RulesDetectorICS
    };
}
