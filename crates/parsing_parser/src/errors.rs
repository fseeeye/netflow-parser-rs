use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ProtocolType;

/// 表示各类解析错误的结构。
/// * `ParsingHeader`: 表示解析当前层协议过程出错。
/// * `UnknowPayload`: 表示无法判断上层协议。
/// * `NotEndPayload`: 表示解析流程已经走完但是依旧还剩余未解析的比特。
/// * `Adaptor`: 在 FFI 适配胶水层发生错误。
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy, Hash, Error)]
pub enum ParseError {
    #[error("Occurs error when parsing {protocol:?} at offset {offset}")]
    ParsingHeader{
        protocol: ProtocolType,
        offset: usize
    },
    #[error("Can't choose next level protocol.")]
    UnknownPayload,
    #[error("Remain some bytes when complete parsing.")]
    NotEndPayload,
    #[error("Occurs error at FFI adaptor layer.")]
    Adaptor,
}
