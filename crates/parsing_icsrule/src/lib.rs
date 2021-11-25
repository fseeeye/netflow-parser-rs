//! ICS 匹配规则
//! 
//! 由于规则字符串设计为 Json 格式，且为所有规则数据结构实现了 Serialize/Deserialize，
//! 所以我们源码不必再实现规则从 Json 解析至 Rust 数据结构的代码。
mod detect;
mod rule;
mod rule_arg;

pub use rule::Rules;
pub use detect::{detect_ics, CheckResult};