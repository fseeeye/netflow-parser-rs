use std::str::FromStr;

use nom::IResult;

use super::types;
use super::SuruleParseError;

/*
 *  Utility Parsers
 */

/// 处理输入
#[inline(always)]
fn handle_value(input: &str) -> Result<&str, nom::Err<SuruleParseError<&str>>> {
    let input = input.trim();
    if input.is_empty() {
        Err(SuruleParseError::EmptyStr.into())
    } else {
        Ok(input)
    }
}

/// 处理输入
#[inline(always)]
fn handle_stream(input: &str) -> Result<&str, nom::Err<SuruleParseError<&str>>> {
    let input = input.trim_start();
    if input.is_empty() {
        Err(SuruleParseError::EmptyStr.into())
    } else {
        Ok(input)
    }
}

/// 获得所有字符，直到碰到空白字符
#[inline(always)]
pub(super) fn take_until_whitespace(input: &str) -> IResult<&str, &str, SuruleParseError<&str>> {
    nom::bytes::complete::is_not(" \t\r\n")(input)
}

/// 解析数字 u64
#[inline(always)]
pub(super) fn parse_u64<'a>(
    input: &'a str,
    context: &str,
) -> Result<u64, nom::Err<SuruleParseError<&'a str>>> {
    let u64_str = handle_value(input)?;

    u64_str.parse::<u64>().map_err(|_| {
        SuruleParseError::IntegerParseError(format!("{}: \"{}\"", context, input)).into()
    })
}

/// 解析列表，比如：地址 / 端口列表
///
/// 这函数实际上并不返回数组，而只是解析出完整且正确的列表字符串。
#[allow(dead_code)]
pub(super) fn parse_list(input: &str) -> Result<&str, nom::Err<SuruleParseError<&str>>> {
    let input = handle_value(input)?;
    let mut depth = 0;
    let mut end = 0;
    for (i, c) in input.chars().enumerate() {
        if i == 0 && c != '[' {
            return Err(SuruleParseError::NotList.into());
        }
        end = i;
        match c {
            '[' => {
                depth += 1;
            }
            ']' => {
                depth -= 1;
            }
            _ => {}
        }
        if depth == 0 {
            break;
        }
    }
    if depth != 0 {
        return Err(SuruleParseError::UnterminatedList.into());
    }
    Ok(&input[0..end + 1])
}

/// 从字符流中解析列表
///
/// 该列表可能被 [] 包裹，表示多值；也可能没被包裹，表示单一值
pub(super) fn parse_list_maybe_from_stream(
    input: &str,
) -> IResult<&str, &str, SuruleParseError<&str>> {
    let input = handle_stream(input)?;
    let mut depth = 0;
    let mut end = 0;
    for (i, c) in input.chars().enumerate() {
        if i == 0 && c != '[' {
            // 如果不是 list，直接解析到空白字符
            return take_until_whitespace(input);
        }
        end = i;
        match c {
            '[' => {
                depth += 1;
            }
            ']' => {
                depth -= 1;
            }
            _ => {}
        }
        if depth == 0 {
            break;
        }
    }
    if depth != 0 {
        return Err(SuruleParseError::UnterminatedList.into());
    }
    Ok((&input[end + 1..], &input[0..end + 1]))
}

/*
 *  Rule Element Value Parsers
 */

/// 从字符流中解析 Direction
pub(super) fn parse_direction_from_stream(
    input: &str,
) -> IResult<&str, types::Direction, SuruleParseError<&str>> {
    let input = handle_stream(input)?;
    if let Ok((input, direction)) = nom::branch::alt::<_, _, nom::error::Error<&str>, _>((
        nom::bytes::complete::tag("->"),
        nom::bytes::complete::tag("<>"),
    ))(input)
    {
        match direction {
            "->" => Ok((input, types::Direction::Single)),
            "<>" => Ok((input, types::Direction::Both)),
            _ => Err(SuruleParseError::InvalidDirection(direction.to_string()).into()),
        }
    } else {
        Err(SuruleParseError::InvalidDirection(input.to_string()).into())
    }
}

/// 解析 CountOrName
pub(super) fn parse_count_or_name(
    input: &str,
) -> Result<types::CountOrName, nom::Err<SuruleParseError<&str>>> {
    let input = handle_value(input)?;
    // 如果 input 没能解析成功为 CountOrName::Value(i64)，那么就作为 CountOrName::Var(String)
    if let Ok(distance) = input.parse::<i64>() {
        Ok(types::CountOrName::Value(distance))
    } else {
        Ok(types::CountOrName::Var(input.to_string()))
    }
}

/// 解析 ByteJump
pub(super) fn parse_byte_jump(
    input: &str,
) -> Result<types::ByteJump, nom::Err<SuruleParseError<&str>>> {
    // 内部工具函数：创建解析错误
    let make_error = |reason| SuruleParseError::InvalidByteJump(reason).into();

    let input = handle_value(input)?;
    // step1: 逗号分割字符串
    let (_, values) = nom::multi::separated_list1::<_, _, _, nom::error::Error<&str>, _, _>(
        nom::bytes::complete::tag(","),
        nom::sequence::preceded(
            nom::character::complete::multispace0,
            nom::bytes::complete::is_not(","),
        ),
    )(input)
    .map_err(|_| make_error(format!("invalid input: {}", input)))?;
    if values.len() < 2 {
        return Err(make_error("no enough arguments".into()));
    }

    // step2: 从 Vec 中依次解析 ByteJump 各字段
    let mut byte_jump = types::ByteJump {
        count: values[0]
            .trim()
            .parse()
            // wrap nom error
            .map_err(|_| make_error(format!("invalid count: {}", values[0])))?,
        offset: values[1]
            .trim()
            .parse()
            .map_err(|_| make_error(format!("invalid offset: {}", values[1])))?,
        ..Default::default()
    };

    // 解析可选字段
    for value in values[2..].iter() {
        let (value, name) = take_until_whitespace(value)
            .map_err(|_| make_error(format!("invalid value: {}", value)))?;
        match name {
            "relative" => byte_jump.relative = true,
            "little" => {
                byte_jump.endian = types::Endian::Little;
            }
            "big" => {
                byte_jump.endian = types::Endian::Big;
            }
            "align" => {
                byte_jump.align = true;
            }
            "from_beginning" => {
                byte_jump.from_beginning = true;
            }
            "from_end" => {
                byte_jump.from_end = true;
            }
            "dce" => {
                byte_jump.dce = true;
            }
            "string" => {
                byte_jump.string = true;
            }
            "hex" => {
                byte_jump.hex = true;
            }
            "dec" => {
                byte_jump.dec = true;
            }
            "oct" => {
                byte_jump.oct = true;
            }
            "multiplier" => {
                byte_jump.multiplier = value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| make_error(format!("invalid multiplier: \"{}\"", value)))?;
            }
            "post_offset" => {
                byte_jump.post_offset = value
                    .trim()
                    .parse::<i64>()
                    .map_err(|_| make_error(format!("invalid post_offset: \"{}\"", value)))?;
            }
            "bitmask" => {
                let value = value.trim();
                let trimmed = if value.starts_with("0x") || value.starts_with("0X") {
                    &value[2..]
                } else {
                    value
                };
                let value = u64::from_str_radix(trimmed, 16)
                    .map_err(|_| make_error(format!("invalid bitmask: \"{}\"", value)))?;
                byte_jump.bitmask = value;
            }
            _ => {
                return Err(make_error(format!("unknown parameter: \"{}\"", name)));
            }
        }
    }

    Ok(byte_jump)
}

/// 解析 Flowbits
pub(super) fn parse_flowbits(
    input: &str,
) -> Result<types::Flowbits, nom::Err<SuruleParseError<&str>>> {
    // 内部工具函数：创建解析错误
    let make_error = |reason| SuruleParseError::Flowbit(reason).into();

    let input = handle_value(input)?;

    let command_parser = nom::sequence::preceded(
        nom::character::complete::multispace0,
        nom::character::complete::alphanumeric1,
    );
    let name_parser = nom::sequence::preceded(
        nom::bytes::complete::tag(","),
        nom::sequence::preceded(nom::character::complete::multispace0, nom::combinator::rest),
    );

    let (_, (command, names)) =
        nom::sequence::tuple((command_parser, nom::combinator::opt(name_parser)))(input)?;
    let command = types::FlowbitCommand::from_str(command)?;

    match command {
        types::FlowbitCommand::IsNotSet
        | types::FlowbitCommand::Unset
        | types::FlowbitCommand::Toggle
        | types::FlowbitCommand::IsSet
        | types::FlowbitCommand::Set => {
            let names = names
                .ok_or_else(|| make_error(format!("{} requires argument", command)))?
                .split('|')
                .map(|s| s.trim().to_string())
                .collect();
            Ok(types::Flowbits { command, names })
        }
        types::FlowbitCommand::NoAlert => {
            if names.is_some() {
                Err(make_error("noalert don't need any arguments".to_string()))
            } else {
                Ok(types::Flowbits {
                    command,
                    names: vec![],
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_number_str() {
        let num_rst = parse_u64(" 12\r\n", "depth").unwrap();
        assert_eq!(num_rst, 12u64);
    }

    #[test]
    fn test_list_str() {
        // Ok
        assert_eq!(parse_list("[]"), Ok("[]"));
        assert_eq!(parse_list("[1,[1,2],[1,2,3]]a"), Ok("[1,[1,2],[1,2,3]]"));
        assert_eq!(parse_list(" [[hel]lo]a\r\n"), Ok("[[hel]lo]"));
        // Err
        assert_eq!(parse_list(""), Err(SuruleParseError::EmptyStr.into()));
        assert_eq!(parse_list("\r"), Err(SuruleParseError::EmptyStr.into()));
        assert_eq!(parse_list("]"), Err(SuruleParseError::NotList.into()));
        assert_eq!(parse_list("{1,2}"), Err(SuruleParseError::NotList.into()));
        assert_eq!(
            parse_list("[[1,2]"),
            Err(SuruleParseError::UnterminatedList.into())
        );
    }

    #[test]
    fn test_direction() {
        // Ok
        assert_eq!(
            parse_direction_from_stream("->"),
            Ok(("", types::Direction::Single))
        );
        assert_eq!(
            parse_direction_from_stream("<>"),
            Ok(("", types::Direction::Both))
        );
        assert_eq!(
            parse_direction_from_stream(" <>a\n"),
            Ok(("a\n", types::Direction::Both))
        );
        // Err
        assert_eq!(
            parse_direction_from_stream(""),
            Err(SuruleParseError::EmptyStr.into())
        );
        assert_eq!(
            parse_direction_from_stream("xx<>"),
            Err(SuruleParseError::InvalidDirection("xx<>".into()).into())
        );
    }

    #[test]
    fn test_count_or_name() {
        // Ok
        assert_eq!(
            parse_count_or_name("123"),
            Ok(types::CountOrName::Value(123))
        );
        assert_eq!(
            parse_count_or_name("foo"),
            Ok(types::CountOrName::Var("foo".into()))
        );
        assert_eq!(
            parse_count_or_name(" 1aa\r\n"),
            Ok(types::CountOrName::Var("1aa".into()))
        );
        // Err
        assert_eq!(
            parse_count_or_name(""),
            Err(SuruleParseError::EmptyStr.into())
        );
    }

    #[test]
    fn test_byte_jump() {
        // Ok
        assert_eq!(
            parse_byte_jump("4,12"),
            Ok(types::ByteJump {
                count: 4,
                offset: 12,
                ..Default::default()
            })
        );
        assert_eq!(
            parse_byte_jump("4,12,,"),
            Ok(types::ByteJump {
                count: 4,
                offset: 12,
                ..Default::default()
            })
        );
        // Err
        assert_eq!(parse_byte_jump(""), Err(SuruleParseError::EmptyStr.into()));
        assert_eq!(
            parse_byte_jump("4"),
            Err(SuruleParseError::InvalidByteJump("no enough arguments".into()).into())
        );
        assert_eq!(
            parse_byte_jump("4,12,multiplier"),
            Err(SuruleParseError::InvalidByteJump("invalid multiplier: \"\"".into()).into())
        );
    }

    #[test]
    fn test_parse_flowbits() {
        assert_eq!(
            parse_flowbits("set,foo.bar"),
            Ok(types::Flowbits {
                command: types::FlowbitCommand::Set,
                names: vec!["foo.bar".into()]
            })
        );
        let _flowbits = parse_flowbits("set,foo | bar").unwrap();
        let _flowbits = parse_flowbits("noalert").unwrap();
    }
}
