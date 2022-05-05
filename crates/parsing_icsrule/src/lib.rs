//! ICS 匹配规则
//!
//! 由于规则字符串设计为 Json 格式，且为所有规则数据结构实现了 Serialize/Deserialize，
//! 所以我们源码不必再实现规则从 Json 解析至 Rust 数据结构的代码。
// unstable feature1 - option result contains: https://doc.rust-lang.org/beta/unstable-book/library-features/option-result-contains.html
#![feature(option_result_contains)]

mod detect;
mod detect_utils;
mod icsrule;
mod icsrule_arg;
mod rule_utils;

pub use icsrule::{HmIcsRules, IcsRule, IcsRuleBasis};
