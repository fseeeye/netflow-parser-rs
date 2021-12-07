use nom::IResult;

use crate::surule::{
    // mod
    elements,
    utils,
    SuruleOption,
    // structures
    SuruleParseError,
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

/// 从字符流中，解析一个通用可选字段元素
///
/// Warning: 后续优化中，需要根据协议采用不同的 parse_xxx_option_element 函数
pub(crate) fn parse_option_element(input: &str) -> IResult<&str, SuruleOption, SuruleParseError> {
    let (input, (name_str, sep)) = take_option_name(input)?;
    if sep == ';' {
        // name_str 是不含值的 option 字段
        Ok((input, name_str.into()))
    } else {
        // name_str 是含值的 option 字段
        let (input, value_str) = take_option_value(input)?;
        let surule_element = match name_str {
            "byte_jump" => SuruleOption::ByteJump(value_str.parse()?),
            "classtype" => SuruleOption::Classtype(value_str.to_owned()),
            "content" => SuruleOption::Content(elements::Content::new(value_str.to_owned())),
            "depth" => SuruleOption::Depth(elements::parse_u64(value_str)?),
            "distance" => SuruleOption::Distance(elements::Distance(value_str.parse()?)),
            "dsize" => SuruleOption::Dsize(value_str.to_owned()),
            "flow" => SuruleOption::Flow(value_str.parse()?),
            "flowbits" => SuruleOption::Flowbits(value_str.parse()?),
            "isdataat" => SuruleOption::IsDataAt(value_str.to_owned()),
            "metadata" => SuruleOption::Metadata(value_str.to_owned()),
            "msg" => SuruleOption::Message(utils::strip_quotes(value_str)),
            "offset" => SuruleOption::Offset(elements::parse_u64(value_str)?),
            "pcre" => SuruleOption::Pcre(value_str.to_owned()),
            "reference" => SuruleOption::Reference(value_str.to_owned()),
            "rev" => SuruleOption::Rev(elements::parse_u64(value_str)?),
            "sid" => SuruleOption::Sid(elements::parse_u64(value_str)?),
            "within" => SuruleOption::Within(elements::Within(value_str.parse()?)),
            _ => SuruleOption::GenericOption(elements::GenericOption {
                name: name_str.to_string(),
                val: Some(value_str.to_string()),
            }),
        };
        Ok((input, surule_element))
    }
}
