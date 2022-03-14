//! Suricata 规则集合
mod vec_surules;

pub use vec_surules::VecSurules;

use crate::SuruleParseError;
use parsing_rule::RulesDetector;
/// Suricata 规则集的数据结构接口
///
/// 方便未来扩展实现更多的 Suricata 规则集数据结构
pub trait Surules: RulesDetector {
    // ref: https://users.rust-lang.org/t/returning-option-self-in-a-trait/28081/2
    fn init_from_file(filepath: &str) -> Result<Self, SuruleParseError>
    where
        Self: Sized;
    fn load_from_file(&mut self, filepath: &str) -> Result<(), SuruleParseError>
    where
        Self: Sized;
}
