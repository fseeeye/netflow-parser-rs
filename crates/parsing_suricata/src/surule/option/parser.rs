use nom::IResult;

use crate::surule::{
    // mod
    elements,
    utils,
    SuruleOption,
    // structures
    SuruleParseError,
};

use super::{
    SuruleFlowOption, SuruleFtpOption, SuruleHttpOption, SuruleMetaOption,
    SuruleNaivePayloadOption, SuruleOtherOption,
};

/// 从字符流中取出 含值可选元素 的值字符串
///
/// 该函数获得 ':' 后面的所有字符(input)，随后将第一个 ';' 前后的所有字符分为两组返回，
/// 不包含第一个 ';'。
fn take_option_value(input: &str) -> IResult<&str, &str, SuruleParseError> {
    let mut escaped_flag = false;
    let mut end;

    // 跳过开头的空白字符
    let input = input.trim_start();

    // 获得第一个 ';' 的位置
    for (i, c) in input.chars().enumerate() {
        end = i;
        if c == '\\' {
            escaped_flag = true;
        }
        // 跳过 '\;'
        else if escaped_flag {
            escaped_flag = false;
        } else if c == ';' {
            // 不返回 ';'
            return Ok((&input[end + 1..], &input[0..end].trim_end()));
        }
    }

    Err(nom::Err::Error(
        SuruleParseError::UnterminatedRuleOptionValue,
    ))
}

/// 从字符流中取出 可选元素 的名称和其后面的符号
fn take_option_name(input: &str) -> IResult<&str, (&str, char), SuruleParseError> {
    let mut escaped_flag = false;
    let mut end;

    // 跳过开头的空白字符
    let input = input.trim_start();

    // 获得第一个 ';' / ':' 的位置
    for (i, c) in input.chars().enumerate() {
        end = i;
        if c == '\\' {
            escaped_flag = true;
        }
        // 跳过 '\;' '\:'
        else if escaped_flag {
            escaped_flag = false;
        } else if c == ';' || c == ':' {
            // 返回 name 和 符号
            return Ok((&input[end + 1..], (&input[0..end].trim_end(), c)));
        }
    }

    Err(nom::Err::Error(
        SuruleParseError::UnterminatedRuleOptionName,
    ))
}

// 解析不含值得 option 字段(bool)，可以通过 &str 直接转换为 SuruleElement
impl From<&str> for SuruleOption {
    fn from(name_str: &str) -> Self {
        match name_str {
            "endswith" => Self::Payload(SuruleNaivePayloadOption::EndsWith),
            "fast_pattern" => Self::Payload(SuruleNaivePayloadOption::FastPattern),
            "file_data" => Self::HTTP(SuruleHttpOption::FileData(elements::FileData)),
            "ftpbounce" => Self::FTP(SuruleFtpOption::FtpBounce),
            "noalert" => Self::Other(SuruleOtherOption::NoAlert),
            "nocase" => Self::Payload(SuruleNaivePayloadOption::NoCase),
            "rawbytes" => Self::Payload(SuruleNaivePayloadOption::RawBytes),
            "startswith" => Self::Payload(SuruleNaivePayloadOption::StartsWith),
            _ => Self::Generic(elements::GenericOption {
                name: name_str.to_string(),
                val: None,
            }),
        }
    }
}

/// 从字符流中，解析一个通用可选字段元素
///
/// Warning: 后续优化中，需要根据协议采用不同的 parse_xxx_option_element 函数
pub(crate) fn parse_option_from_stream(
    input: &str,
) -> IResult<&str, SuruleOption, SuruleParseError> {
    let (input, (name_str, sep)) = take_option_name(input)?;
    if sep == ';' {
        // name_str 是不含值的 option 字段
        Ok((input, name_str.into()))
    } else {
        // name_str 是含值的 option 字段
        let (input, value_str) = take_option_value(input)?;
        let surule_element = match name_str {
            "byte_jump" => {
                SuruleOption::Payload(SuruleNaivePayloadOption::ByteJump(value_str.parse()?))
            }
            "byte_test" => {
                SuruleOption::Payload(SuruleNaivePayloadOption::ByteTest(value_str.parse()?))
            }
            "classtype" => SuruleOption::Meta(SuruleMetaOption::Classtype(value_str.to_string())),
            "content" => SuruleOption::Payload(SuruleNaivePayloadOption::Content(
                utils::strip_quotes(value_str).parse()?,
            )),
            "depth" => SuruleOption::Payload(SuruleNaivePayloadOption::Depth(
                elements::parse_usize(value_str)?,
            )),
            "distance" => SuruleOption::Payload(SuruleNaivePayloadOption::Distance(
                elements::parse_isize(value_str)?,
            )),
            "dsize" => SuruleOption::Payload(SuruleNaivePayloadOption::Dsize(value_str.parse()?)),
            "flow" => SuruleOption::Flow(SuruleFlowOption::Flow(value_str.parse()?)),
            "flowbits" => SuruleOption::Flow(SuruleFlowOption::Flowbits(value_str.parse()?)),
            "isdataat" => {
                SuruleOption::Payload(SuruleNaivePayloadOption::IsDataAt(value_str.parse()?))
            }
            "metadata" => SuruleOption::Meta(SuruleMetaOption::Metadata(elements::parse_metadata(
                value_str,
            )?)),
            "msg" => SuruleOption::Meta(SuruleMetaOption::Message(utils::strip_quotes(value_str))),
            "offset" => SuruleOption::Payload(SuruleNaivePayloadOption::Offset(
                elements::parse_usize(value_str)?,
            )),
            "pcre" => SuruleOption::Payload(SuruleNaivePayloadOption::Pcre(value_str.parse()?)),
            "reference" => SuruleOption::Meta(SuruleMetaOption::Reference(value_str.to_string())),
            "rev" => SuruleOption::Meta(SuruleMetaOption::Rev(elements::parse_u64(value_str)?)),
            "sid" => SuruleOption::Meta(SuruleMetaOption::Sid(elements::parse_usize(value_str)?)),
            "within" => SuruleOption::Payload(SuruleNaivePayloadOption::Within(
                elements::parse_usize(value_str)?,
            )),
            _ => SuruleOption::Generic(elements::GenericOption {
                name: name_str.to_string(),
                val: Some(value_str.to_string()),
            }),
        };
        Ok((input, surule_element))
    }
}
