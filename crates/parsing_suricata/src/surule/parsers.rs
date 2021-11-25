use std::str::FromStr;

use nom::IResult;
use anyhow::{anyhow, Result};

use super::types;
use super::SuruleParseError;
use super::types::Flowbits;


/*
 *  Utility Parsers
 */
/// 获得所有字符，直到碰到空白字符
#[inline(always)]
fn take_until_whitespace(input: &str) -> IResult<&str, &str, SuruleParseError<&str>> {
    if input.is_empty() { return Ok((input, "")); }
    nom::bytes::complete::is_not(" \t\r\n")(input)
}

/// 处理输入
#[inline(always)]
fn handle_input(input: &str) -> Result<&str, SuruleParseError<&str>> {
    let input = input.trim();
    if input.is_empty() {
        Err(SuruleParseError::EmptyStr)
    } else {
        Ok(input)
    }
}

/// 解析数字 u64
#[inline(always)]
pub(super) fn parse_u64<'a>(
    input: &'a str, 
    context: &str
) -> Result<u64, SuruleParseError<&'a str>> {
    let u64_str = handle_input(input)?;

    u64_str
        .parse::<u64>()
        .map_err(|_| {
            SuruleParseError::IntegerParseError(
                format!("{}: \"{}\"", context, input)
            )
        })
}

/// 解析列表，比如：地址 / 端口列表
/// 
/// 这函数实际上并不返回数组，而只是解析出完整且正确的列表字符串。
pub(super) fn parse_list(input: &str) -> Result<&str, SuruleParseError<&str>> {
    let input = handle_input(input)?;
    let mut depth = 0;
    let mut end = 0;
    for (i, c) in input.chars().enumerate() {
        if i == 0 && c != '[' {
            return Err(SuruleParseError::NotList);
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
        return Err(SuruleParseError::UnterminatedList);
    }
    Ok(&input[0..end + 1])
}


/*
 *  Rule Element Parsers
 */
/// 解析 Direction
pub(super) fn parse_direction(input: &str) -> Result<types::Direction, SuruleParseError<&str>> {
    let input = handle_input(input)?;
    if let Ok((_, direction)) = nom::branch::alt::<_, _, nom::error::Error<&str>, _>(
        (nom::bytes::complete::tag("->"), nom::bytes::complete::tag("<>"))
    )(input) {
        match direction {
            "->" => Ok(types::Direction::Single),
            "<>" => Ok(types::Direction::Both),
            _ => Err(SuruleParseError::InvalidDirection(direction.to_string()))
        }
    } else {
        return Err(SuruleParseError::InvalidDirection(input.to_string()));
    }
}

/// 解析 CountOrName
pub(super) fn parse_count_or_name(input: &str) -> Result<types::CountOrName, SuruleParseError<&str>> {
    let input = handle_input(input)?;
    // 如果 input 没能解析成功为 CountOrName::Value(i64)，那么就作为 CountOrName::Var(String)
    if let Ok(distance) = input.parse::<i64>() {
        Ok(types::CountOrName::Value(distance))
    } else {
        Ok(types::CountOrName::Var(input.to_string()))
    }
}

/// 解析 ByteJump
pub(super) fn parse_byte_jump(input: &str) -> Result<types::ByteJump, SuruleParseError<&str>> {
    // 内部工具函数：创建解析错误
    #[inline(always)]
    fn make_error(reason: String) -> SuruleParseError<&'static str> {
        SuruleParseError::InvalidByteJump(reason)
    }

    let input = handle_input(input)?;
    // step1: 逗号分割字符串
    let (_, values) = nom::multi::separated_list1::<_,_,_,nom::error::Error<&str>,_,_>(
            nom::bytes::complete::tag(","),
            nom::sequence::preceded(
                nom::character::complete::multispace0,
                nom::bytes::complete::is_not(",")
            )
        )(input)
        .map_err(|_| make_error(format!("invalid input: {}", input)))?;
    if values.len() < 2 {
        return Err(make_error("no enough arguments".into()));
    }

    // step2: 从 Vec 中依次解析 ByteJump 各字段
    let mut byte_jump = types::ByteJump::default();
    // 解析必要字段
    byte_jump.count = values[0]
        .trim()
        .parse()
        // wrap nom error
        .map_err(|_| make_error(format!("invalid count: {}", values[0])))?;
    
    byte_jump.offset = values[1]
        .trim()
        .parse()
        .map_err(|_| make_error(format!("invalid offset: {}", values[1])))?;

    // 解析可选字段
    for value in values[2..].into_iter() {
        let (value, name) = take_until_whitespace(value)
            .map_err(|_| make_error(format!("invalid value: {}", value)))?;
        match name {
            "relative" => {
                byte_jump.relative = true
            }
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
pub(super) fn parse_flowbits(input: &str) -> IResult<&str, types::Flowbits, SuruleParseError<&str>> {
    fn make_error<S: AsRef<str>>(reason: S) -> nom::Err<SuruleParseError<&'static str>> {
        nom::Err::Error(SuruleParseError::Flowbit(reason.as_ref().to_string()))
    }

    let input = match handle_input(input) {
        Ok(o) => o,
        Err(e) => return Err(nom::Err::Error(e))
    };

    let command_parser = nom::sequence::preceded(
        nom::character::complete::multispace0,
        nom::character::complete::alphanumeric1
    );
    let name_parser = nom::sequence::preceded(
        nom::bytes::complete::tag(","),
        nom::sequence::preceded(
                nom::character::complete::multispace0, 
                nom::combinator::rest
            )
    );

    let (input_clear, (command, names)) = nom::sequence::tuple((command_parser, nom::combinator::opt(name_parser)))(input)?;
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
            Ok((input, types::Flowbits { command, names }))
        }
        types::FlowbitCommand::NoAlert => {
            if names.is_some() {
                Err(make_error("noalert don't need any arguments"))
            } else {
                Ok((
                    input,
                    types::Flowbits {
                        command,
                        names: vec![],
                    },
                ))
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
        assert_eq!(parse_list(""), Err(SuruleParseError::EmptyStr));
        assert_eq!(parse_list("\r"), Err(SuruleParseError::EmptyStr));
        assert_eq!(parse_list("]"), Err(SuruleParseError::NotList));
        assert_eq!(parse_list("{1,2}"), Err(SuruleParseError::NotList));
        assert_eq!(parse_list("[[1,2]"), Err(SuruleParseError::UnterminatedList));
    }

    #[test]
    fn test_direction() {
        // Ok
        assert_eq!(parse_direction("->"), Ok(types::Direction::Single));
        assert_eq!(parse_direction("<>"), Ok(types::Direction::Both));
        assert_eq!(parse_direction(" <>a\n"), Ok(types::Direction::Both));
        // Err
        assert_eq!(parse_direction(""), Err(SuruleParseError::EmptyStr));
        assert_eq!(parse_direction("xx<>"), Err(SuruleParseError::InvalidDirection("xx<>".into())));
    }

    #[test]
    fn test_count_or_name() {
        // Ok
        assert_eq!(parse_count_or_name("123"), Ok(types::CountOrName::Value(123)));
        assert_eq!(parse_count_or_name("foo"), Ok(types::CountOrName::Var("foo".into())));
        assert_eq!(parse_count_or_name(" 1aa\r\n"), Ok(types::CountOrName::Var("1aa".into())));
        // Err
        assert_eq!(parse_count_or_name(""), Err(SuruleParseError::EmptyStr));
    }

    #[test]
    fn test_byte_jump() {
        // Ok
        assert_eq!(parse_byte_jump("4,12"), Ok(types::ByteJump {
            count: 4,
            offset: 12,
            ..Default::default()
        }));
        assert_eq!(parse_byte_jump("4,12,,"), Ok(types::ByteJump {
            count: 4,
            offset: 12,
            ..Default::default()
        }));
        // Err
        assert_eq!(
            parse_byte_jump(""), 
            Err(SuruleParseError::EmptyStr));
        assert_eq!(
            parse_byte_jump("4"), 
            Err(SuruleParseError::InvalidByteJump("no enough arguments".into())));
        assert_eq!(
            parse_byte_jump("4,12,multiplier"), 
            Err(SuruleParseError::InvalidByteJump("invalid multiplier: \"\"".into()))
        );
    }

    #[test]
    fn test_parse_flowbits() {
        assert_eq!(parse_flowbits("set,foo.bar"), 
            Ok(("set,foo.bar", 
                types::Flowbits{
                    command: types::FlowbitCommand::Set,
                    names: vec!["foo.bar".into()]
                }
            ))
        );
        let (_, _flowbits) = parse_flowbits("set,foo | bar").unwrap();
        let (_, _flowbits) = parse_flowbits("noalert").unwrap();
    }
}