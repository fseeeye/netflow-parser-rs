use nom::IResult;

use std::str::FromStr;

use crate::surule::SuruleParseError;
use crate::surule::utils::strip_brackets;

/// 处理已被从字符流中提取出来的输入
#[inline(always)]
pub(super) fn handle_value(input: &str) -> Result<&str, nom::Err<SuruleParseError>> {
    let input = input.trim();
    if input.is_empty() {
        Err(SuruleParseError::EmptyStr.into())
    } else {
        Ok(input)
    }
}

/// 处理字符流输入
#[inline(always)]
pub(super) fn handle_stream(input: &str) -> Result<&str, nom::Err<SuruleParseError>> {
    let input = input.trim_start();
    if input.is_empty() {
        Err(SuruleParseError::EmptyStr.into())
    } else {
        Ok(input)
    }
}

/// 获得所有字符，直到碰到空白字符
#[inline(always)]
pub(super) fn take_until_whitespace(input: &str) -> IResult<&str, &str, SuruleParseError> {
    nom::bytes::complete::is_not(" \t\r\n")(input)
}

/// 从字符流中解析列表
///
/// 这函数实际上并不返回数组，而只是解析出完整且正确的列表字符串。
/// 该列表可能被 [] 包裹，表示多值；也可能没被包裹，表示单一值
pub(super) fn take_list_maybe_from_stream(input: &str) -> IResult<&str, &str, SuruleParseError> {
    let mut depth = 0;
    let mut end = 0;
    let input = handle_stream(input)?;

    if !(input.starts_with("[")) && !(input.starts_with("![")) {
        // 如果不是 list，直接解析到空白字符
        return take_until_whitespace(input);
    }

    for (i, c) in input.chars().enumerate() {
        end = i;
        match c {
            '[' => {
                depth += 1;
                if depth > 2 {
                    return Err(SuruleParseError::ListDeepthOverflow.into());
                }
            }
            ']' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(SuruleParseError::UnterminatedList.into());
    }
    Ok((&input[end + 1..], &input[0..end + 1]))
}

/// 从列表字符串中提取出元素
pub(super) fn take_list_members(input: &str) -> Result<Vec<&str>, nom::Err<SuruleParseError>> {
    let mut members = Vec::new();
    let mut depth: usize = 0;
    let mut start: usize;
    let mut end: usize;
    let mut is_in_list: bool = false;
    let input = handle_value(input)?;

    if (input.starts_with("[")) && input.ends_with("]") {
        start = 1;
    } else if input.starts_with("![") && input.ends_with("]") {
        start = 2;
    } else {
        return Err(SuruleParseError::NotList.into());
    }

    for (i, c) in input.chars().enumerate() {
        end = i;
        match c {
            '[' => {
                depth += 1;
                if depth == 2 {
                    is_in_list = true;
                } else if depth > 2 {
                    return Err(SuruleParseError::ListDeepthOverflow.into());
                }
            }
            ']' => {
                depth -= 1;
                if depth == 1 {
                    is_in_list = false;
                } else if depth == 0 {
                    members.push(&input[start..end]);
                    break;
                }
            }
            ',' => {
                if !is_in_list {
                    members.push(&input[start..end]);
                    start = end + 1;
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(SuruleParseError::UnterminatedList.into());
    }

    Ok(members)
}

// parse_list_from_stream 的辅助函数
// 解析 list (不含 exception 和 nested list)
pub(super) fn parse_inner_list<T>(
    input: &str,
    list_vec: &mut Option<Vec<T>>,
) -> Result<(), nom::Err<SuruleParseError>>
where
    T: FromStr<Err = nom::Err<SuruleParseError>>,
{
    let list_split = strip_brackets(input).split(',');
    for s in list_split {
        let s = handle_value(s)
            .map_err(|_| SuruleParseError::InvalidList("empty list value.".to_string()).into())?;
        // list 中不会再包含 exception / nested list
        let ip = T::from_str(s)?;
        if let Some(v) = list_vec {
            v.push(ip);
        } else {
            *list_vec = Some(vec![ip]);
        }
    }
    Ok(())
}