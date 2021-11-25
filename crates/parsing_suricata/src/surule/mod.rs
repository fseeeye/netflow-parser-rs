//! 解析 suricata 规则字符串
//! 
//! 解析得到的 Surule 数据结构支持序列化/反序列化，可以简单地撰写程序将该规则转换成 Json / YAML 格式。
mod error;
mod parsers;
mod surule;
mod types;
mod utils;

pub use error::SuruleParseError;

