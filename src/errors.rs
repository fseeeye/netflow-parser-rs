/// 表示各类解析错误的结构。
/// * `ParsingHeader`: 表示解析当前层协议过程出错。
/// * `ParsingPayload`: 表示解析判断payload类型所需字段的过程中出错。
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum ParseError<'a> {
    ParsingHeader(&'a [u8]),
    ParsingPayload(&'a [u8]),
    UnknownPayload(&'a [u8]),
    NotEndPayload(&'a [u8]),
}
