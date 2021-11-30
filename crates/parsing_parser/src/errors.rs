use serde::{Serialize, Deserialize};

/// 表示各类解析错误的结构。
/// * `ParsingHeader`: 表示解析当前层协议过程出错。
/// * `ParsingPayload`: 表示解析判断payload类型所需字段的过程中出错。
#[derive(Serialize, Deserialize)]
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum ParseError {
    ParsingHeader,
    ParsingPayload,
    UnknownPayload,
    NotEndPayload,
}
