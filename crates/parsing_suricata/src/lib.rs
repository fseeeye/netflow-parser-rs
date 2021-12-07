//! suricata 规则解析与匹配
//!
//! 应包含的功能：
//! - 从文件/输入，解析 suricata 规则字符串的能力
//! - 配合 parsing_parser 库，进行 suricata 黑名单规则与协议解析结果匹配的能力
//!
//! 参考项目：
//!  - suricata 规则字符串解析参考自：[rust-suricata-rule-parser](https://github.com/jasonish/rust-suricata-rule-parser/blob/main/src/lib.rs)
mod detect;
mod surule;

pub use surule::{
    // structs
    Surule,
    SuruleOption,
    SuruleParseError,
    // traits
    Surules,
    VecSurules,
};
