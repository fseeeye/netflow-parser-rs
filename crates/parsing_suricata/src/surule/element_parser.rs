use std::str::FromStr;

use nom::IResult;
use anyhow::Result;

use parsing_parser::{TransportProtocol, NetworkProtocol};

use super::types;
use super::SuruleParseError;
use super::utils::{strip_quotes, strip_brackets};


/*
 *  Utility Parsers
 */

/// 处理已被从字符流中提取出来的输入
#[inline(always)]
pub(super) fn handle_value(input: &str) -> Result<&str, nom::Err<SuruleParseError<&'static str>>> {
    let input = input.trim();
    if input.is_empty() {
        Err(SuruleParseError::EmptyStr.into())
    } else {
        Ok(input)
    }
}

/// 处理字符流输入
#[inline(always)]
pub(super) fn handle_stream(input: &str) -> Result<&str, nom::Err<SuruleParseError<&'static str>>> {
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

/// 从字符流中解析列表
///
/// 这函数实际上并不返回数组，而只是解析出完整且正确的列表字符串。
/// 该列表可能被 [] 包裹，表示多值；也可能没被包裹，表示单一值
pub(super) fn take_list_maybe_from_stream(
    input: &str,
) -> IResult<&str, &str, SuruleParseError<&str>> {
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
                    return Err(SuruleParseError::ListDeepthOverflow.into())
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
        // if depth == 0 && !(c == '!' && i == 0) {
        //     break;
        // }
    }
    if depth != 0 {
        return Err(SuruleParseError::UnterminatedList.into())
    }
    Ok((&input[end + 1..], &input[0..end + 1]))
}

/// 从列表字符串中提取出元素
pub(super) fn take_list_members(
    input: &str
) -> Result<Vec<&str>, nom::Err<SuruleParseError<&'static str>>> {
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
                }
                else if depth > 2 {
                    return Err(SuruleParseError::ListDeepthOverflow.into())
                }
            }
            ']' => {
                depth -= 1;
                if depth == 1 {
                    is_in_list = false;
                }
                else if depth == 0 {
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
        return Err(SuruleParseError::UnterminatedList.into())
    }

    Ok(members)
}

/*
 *  Rule Header Element Parsers
 */

/// 从字符流中解析 Action
pub(super) fn parse_action_from_stream(
    input: &str
) -> IResult<&str, types::Action, SuruleParseError<&str>> {
    let make_err = |reason| SuruleParseError::InvalidAction(reason).into();

    let input = handle_stream(input)
        .map_err(|_| make_err("empty stream.".to_string()))?;
    let (input, action_str) = take_until_whitespace(input)
        .map_err(|_| make_err(input.to_string()))?;
    let action = match action_str {
        "alert"      => types::Action::Alert,
        "pass"       => types::Action::Pass,
        "drop"       => types::Action::Drop,
        "reject"     => types::Action::Reject,
        "rejectsrc"  => types::Action::RejectSrc,
        "rejectdst"  => types::Action::RejectDst,
        "rejectboth" => types::Action::RejectBoth,
        _ => return Err(SuruleParseError::InvalidAction(action_str.to_string()).into())
    };

    Ok((input, action))
}

/// 从字符流中解析 Protocol
/// 
/// 目前仅支持：tcp / udp / ip
pub(super) fn parse_protocol_from_stream(
    input: &str
) -> IResult<&str, types::Protocol, SuruleParseError<&str>> {
    let make_err = |reason| SuruleParseError::InvalidProtocol(reason).into();

    let input = handle_stream(input)
        .map_err(|_| make_err(input.to_string()))?;
    let (input, protocol_str) = take_until_whitespace(input)
        .map_err(|_| make_err(input.to_string()))?;
    let protocol = match protocol_str {
        "tcp" => types::Protocol::Transport(TransportProtocol::Tcp),
        "udp" => types::Protocol::Transport(TransportProtocol::Udp),
        "ip"  => types::Protocol::Network(NetworkProtocol::Ipv4),
        _ => return Err(SuruleParseError::InvalidProtocol(protocol_str.to_string()).into())
    };

    Ok((input, protocol))
}

// parse_ip_list_from_stream 的辅助函数
// 解析 list (不含 exception 和 nested list)
fn parse_inner_list(
    input: &str,
    ip_vec: &mut Option<Vec<types::IpAddress>>
) -> Result<(), nom::Err<SuruleParseError<&'static str>>> {
    let list_split = strip_brackets(input).split(',');
    for s in list_split {
        let s = handle_value(s)
            .map_err(|_| SuruleParseError::InvalidIpList("empty list value.".to_string()).into())?;
        // list 中不会再包含 exception / nested list
        let ip = types::IpAddress::from_str(s)?;
        if let Some(v) = ip_vec {
            v.push(ip);
        } else {
            *ip_vec = Some(vec![ip]);
        }
    }
    Ok(())
}

/// 从字符流中解析 IpAddrress List
pub(super) fn parse_ip_list_from_stream(
    input: &str
) -> IResult<&str, types::IpAddressList, SuruleParseError<&str>> {
    // closures
    let make_err = |reason| SuruleParseError::InvalidIpList(reason).into();
    let push_ip = |ip_vec: &mut Option<Vec<types::IpAddress>> , ip: types::IpAddress| {
        if let Some(v) = ip_vec {
            v.push(ip);
        } else {
            *ip_vec = Some(vec![ip]);
        }
    };
    
    // preprocess
    let input = handle_stream(input)
        .map_err(|_| make_err("empty stream.".to_string()))?;
    let (input, ip_list_string) = take_list_maybe_from_stream(input)
        .map(|(input, list_str)| (input, strip_quotes(list_str)))?;
    let mut ip_list_str = ip_list_string.as_str();

    // parse ip address list
    let mut ip_list = types::IpAddressList::default();
    if ip_list_str.starts_with('!') { // exception: !...
        ip_list_str = &ip_list_str[1..];

        if ip_list_str.starts_with('[') && ip_list_str.ends_with(']') { // exception list: ![..., ...]
            parse_inner_list(ip_list_str, &mut ip_list.except)?;
        } else { // single exception value: !1.1.1.1
            let ip = types::IpAddress::from_str(ip_list_str)?;
            push_ip(&mut ip_list.except, ip);
        }

        Ok((input, ip_list))
    } else { // acception
        if ip_list_str.starts_with('[') && ip_list_str.ends_with(']') { // first list: [..., ...]
            // let ip_list_split = strip_brackets(ip_list_str).split(',');
            for s in take_list_members(ip_list_str)? {
                let s = handle_value(s)
                    .map_err(|_| make_err("empty list value.".to_string()))?;
                if s.starts_with('!') { // exception element: [!...]
                    let s = &s[1..];
                    if s.starts_with('[') && s.ends_with(']') { // exception list: [![..., ...]]
                        parse_inner_list(s, &mut ip_list.except)?;
                    } else { // exception single value: [!1.1.1.1]
                        let ip = types::IpAddress::from_str(s)?;
                        push_ip(&mut ip_list.except, ip);
                    }
                } else { // acception element: [...]
                    if s.starts_with('[') && s.ends_with(']') { // acception list: [[..., ...]]
                        parse_inner_list(s, &mut ip_list.accept)?;
                    } else { // acception single value: [1.1.1.1]
                        let ip = types::IpAddress::from_str(s)?;
                        push_ip(&mut ip_list.accept, ip);
                    }
                }
            }
        } else { // single value: 1.1.1.1
            let ip = types::IpAddress::from_str(ip_list_str)?;
            push_ip(&mut ip_list.accept, ip);
        }

        Ok((input, ip_list))
    }
}

// TODO
// /// 从字符流中解析 Port List
// pub(super) fn parse_port_list_from_stream(
//     input: &str
// ) -> IResult<&str, Vec<u16>, SuruleParseError<&str>> {
//     let make_err = |reason| SuruleParseError::InvalidPortList(reason).into();

//     let input = handle_stream(input)
//         .map_err(|_| make_err("empty stream.".to_string()))?;
//     let (input, port_list_str) = take_list_maybe_from_stream(input)?;

//     if port_list_str.starts_with('[') && port_list_str.ends_with(']') { // it's a port list
//         let mut port_list: Vec<u16> = Vec::new();
//         let port_list_split = port_list_str
//             .strip_prefix('[')
//             .ok_or(make_err(port_list_str.to_string()))?
//             .strip_suffix(']')
//             .ok_or(make_err(port_list_str.to_string()))?
//             .split(',');
//         for p in port_list_split {
//             let p = handle_value(p)
//                 .map_err(|_| make_err("empty value.".to_string()))?;
//             port_list.push(p
//                 .parse::<u16>()
//                 .map_err(|_| make_err(p.to_string()))?)
//         }
//         Ok((input, port_list))
//     } else {
//         let p = handle_value(port_list_str)
//             .map_err(|_| make_err("empty value.".to_string()))?;
//         Ok((
//             input, 
//             vec![p.parse::<u16>().map_err(|_| make_err(p.to_string()))?]
//         ))
//     }
// }

/// 从字符流中解析 Direction
pub(super) fn parse_direction_from_stream(
    input: &str,
) -> IResult<&str, types::Direction, SuruleParseError<&str>> {
    let make_err = |reason| SuruleParseError::InvalidDirection(reason).into();

    let input = handle_stream(input)
        .map_err(|_| make_err("empty stream.".to_string()))?;
    if let Ok((input, direction)) = nom::branch::alt::<_, _, nom::error::Error<&str>, _>((
        nom::bytes::complete::tag("->"),
        nom::bytes::complete::tag("<>"),
    ))(input)
    {
        match direction {
            "->" => Ok((input, types::Direction::Uni)),
            "<>" => Ok((input, types::Direction::Bi)),
            _ => Err(make_err(direction.to_string())),
        }
    } else {
        Err(make_err(input.to_string()))
    }
}


/*
 *  Rule Body Element Value Parsers
 */

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
    let make_err = |reason| SuruleParseError::InvalidByteJump(reason).into();

    let input = handle_value(input)?;
    // step1: 逗号分割字符串
    let (_, values) = nom::multi::separated_list1::<_, _, _, nom::error::Error<&str>, _, _>(
        nom::bytes::complete::tag(","),
        nom::sequence::preceded(
            nom::character::complete::multispace0,
            nom::bytes::complete::is_not(","),
        ),
    )(input)
    .map_err(|_| make_err(format!("invalid input: {}", input)))?;
    if values.len() < 2 {
        return Err(make_err("no enough arguments".into()));
    }

    // step2: 从 Vec 中依次解析 ByteJump 各字段
    let mut byte_jump = types::ByteJump {
        count: values[0]
            .trim()
            .parse()
            // wrap nom error
            .map_err(|_| make_err(format!("invalid count: {}", values[0])))?,
        offset: values[1]
            .trim()
            .parse()
            .map_err(|_| make_err(format!("invalid offset: {}", values[1])))?,
        ..Default::default()
    };

    // 解析可选字段
    for value in values[2..].iter() {
        let (value, name) = take_until_whitespace(value)
            .map_err(|_| make_err(format!("invalid value: {}", value)))?;
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
                    .map_err(|_| make_err(format!("invalid multiplier: \"{}\"", value)))?;
            }
            "post_offset" => {
                byte_jump.post_offset = value
                    .trim()
                    .parse::<i64>()
                    .map_err(|_| make_err(format!("invalid post_offset: \"{}\"", value)))?;
            }
            "bitmask" => {
                let value = value.trim();
                let trimmed = if value.starts_with("0x") || value.starts_with("0X") {
                    &value[2..]
                } else {
                    value
                };
                let value = u64::from_str_radix(trimmed, 16)
                    .map_err(|_| make_err(format!("invalid bitmask: \"{}\"", value)))?;
                byte_jump.bitmask = value;
            }
            _ => {
                return Err(make_err(format!("unknown parameter: \"{}\"", name)));
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
    let make_err = |reason| SuruleParseError::Flowbit(reason).into();

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
                .ok_or_else(|| make_err(format!("{} requires argument", command)))?
                .split('|')
                .map(|s| s.trim().to_string())
                .collect();
            Ok(types::Flowbits { command, names })
        }
        types::FlowbitCommand::NoAlert => {
            if names.is_some() {
                Err(make_err("noalert don't need any arguments".to_string()))
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
    use std::net::Ipv4Addr;

    use ipnet::Ipv4Net;

    use super::*;

    #[test]
    fn test_number_str() {
        let num_rst = parse_u64(" 12\r\n", "depth").unwrap();
        assert_eq!(num_rst, 12u64);
    }

    #[test]
    fn test_take_list_str() {
        // Ok
        assert_eq!(take_list_maybe_from_stream("[]"), Ok(("", "[]")));
        assert_eq!(take_list_maybe_from_stream("[1,[1,2],[1,2,3]]a"), Ok(("a", "[1,[1,2],[1,2,3]]")));
        assert_eq!(take_list_maybe_from_stream(" [[hel]lo]a\r\n"), Ok(("a\r\n", "[[hel]lo]")));
        assert_eq!(take_list_maybe_from_stream("aaa bbb ccc"), Ok((" bbb ccc", "aaa")));
        // Err
        assert_eq!(take_list_maybe_from_stream(""), Err(SuruleParseError::EmptyStr.into()));
        assert_eq!(take_list_maybe_from_stream("\r"), Err(SuruleParseError::EmptyStr.into()));
        assert_eq!(
            take_list_maybe_from_stream("[[1,2]"),
            Err(SuruleParseError::UnterminatedList.into())
        );
    }

    #[test]
    fn test_action() {
        assert_eq!(parse_action_from_stream("alert\n \t xxx"), Ok(("\n \t xxx", types::Action::Alert)));
        assert_eq!(parse_action_from_stream("\t    pass xxx"), Ok((" xxx", types::Action::Pass)));
        assert_eq!(parse_action_from_stream("\n    drop xxx"), Ok((" xxx", types::Action::Drop)));
        assert_eq!(parse_action_from_stream("\r  reject xxx"), Ok((" xxx", types::Action::Reject)));
        assert_eq!(parse_action_from_stream(" rejectsrc xxx"), Ok((" xxx", types::Action::RejectSrc)));
        assert_eq!(parse_action_from_stream(" rejectdst xxx"), Ok((" xxx", types::Action::RejectDst)));
        assert_eq!(parse_action_from_stream("rejectboth xxx"), Ok((" xxx", types::Action::RejectBoth)));
    }

    #[test]
    fn test_protocol() {
        assert_eq!(
            parse_protocol_from_stream(" tcp xxx"),
            Ok((" xxx", types::Protocol::Transport(TransportProtocol::Tcp)))
        );
        assert_eq!(
            parse_protocol_from_stream(" udp xxx"),
            Ok((" xxx", types::Protocol::Transport(TransportProtocol::Udp)))
        );
        assert_eq!(
            parse_protocol_from_stream(" ip xxx"),
            Ok((" xxx", types::Protocol::Network(NetworkProtocol::Ipv4)))
        );
    }

    #[test]
    fn test_ip_list() {
        assert_eq!(
            parse_ip_list_from_stream(r#" !["10.0.0.0/8", "192.168.0.1"] xxx"#),
            Ok((" xxx", types::IpAddressList {
                accept: None,
                except: Some(vec![
                    types::IpAddress::V4Range(Ipv4Net::from_str("10.0.0.0/8").unwrap()),
                    types::IpAddress::V4Addr(Ipv4Addr::from_str("192.168.0.1").unwrap())
                ])
            }))
        );

        assert_eq!(
            parse_ip_list_from_stream(r#" ["10.0.0.0/8",!["10.0.0.1","10.0.0.2"]] xxx"#),
            Ok((" xxx", types::IpAddressList {
                accept: Some(vec![types::IpAddress::V4Range(Ipv4Net::from_str("10.0.0.0/8").unwrap())]),
                except: Some(vec![
                    types::IpAddress::V4Addr(Ipv4Addr::from_str("10.0.0.1").unwrap()),
                    types::IpAddress::V4Addr(Ipv4Addr::from_str("10.0.0.2").unwrap())
                    ])
                }))
            );
        
        // 使用示例
        let (_, rst) = parse_ip_list_from_stream(r#" ["10.0.0.0/8", !["10.0.0.1", "10.0.0.2"]] xxx"#).unwrap();
        let test_ip = Ipv4Addr::from_str("10.0.0.2").unwrap();
        if let Some(a) = rst.except {
            for ia in a {
                match ia {
                    types::IpAddress::V4Addr(addr) => {
                        if addr == test_ip {
                            // do sth.
                            return
                        }
                    },
                    types::IpAddress::V4Range(range) => {
                        if range.contains(&test_ip) {
                            // do sth.
                            return
                        }
                    }
                }
            }
            assert!(false)
        }
    }

    #[test]
    fn test_direction() {
        // Ok
        assert_eq!(
            parse_direction_from_stream("->"),
            Ok(("", types::Direction::Uni))
        );
        assert_eq!(
            parse_direction_from_stream("<>"),
            Ok(("", types::Direction::Bi))
        );
        assert_eq!(
            parse_direction_from_stream(" <>a\n"),
            Ok(("a\n", types::Direction::Bi))
        );
        // Err
        assert_eq!(
            parse_direction_from_stream(""),
            Err(SuruleParseError::InvalidDirection("empty stream.".to_string()).into())
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
