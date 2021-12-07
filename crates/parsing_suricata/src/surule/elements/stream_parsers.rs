//! Header Element 的解析函数，用于从字节流中解析出 Header Element
use std::str::FromStr;

use nom::IResult;

use super::types::*;
use super::util_parsers::*;
use crate::surule::utils::strip_quotes;
use crate::surule::SuruleParseError;

/// 从字符流中解析 Action
pub(crate) fn parse_action_from_stream(input: &str) -> IResult<&str, Action, SuruleParseError> {
    let make_err = |reason| SuruleParseError::InvalidAction(reason).into();

    let input = handle_stream(input).map_err(|_| make_err("empty stream.".to_string()))?;
    let (input, action_str) =
        take_until_whitespace(input).map_err(|_| make_err(input.to_string()))?;
    let action = match action_str {
        "alert" => Action::Alert,
        "pass" => Action::Pass,
        "drop" => Action::Drop,
        "reject" => Action::Reject,
        "rejectsrc" => Action::RejectSrc,
        "rejectdst" => Action::RejectDst,
        "rejectboth" => Action::RejectBoth,
        _ => return Err(SuruleParseError::InvalidAction(action_str.to_string()).into()),
    };

    Ok((input, action))
}

/// 从字符流中解析 Protocol
///
/// 目前仅支持：tcp / udp
/// Warning: 由于 parsing_parser 尚未支持 HTTP 协议，所以目前还无法实现 http 规则
pub(crate) fn parse_protocol_from_stream(input: &str) -> IResult<&str, Protocol, SuruleParseError> {
    let make_err = |reason| SuruleParseError::InvalidProtocol(reason).into();

    let input = handle_stream(input).map_err(|_| make_err(input.to_string()))?;
    let (input, protocol_str) =
        take_until_whitespace(input).map_err(|_| make_err(input.to_string()))?;
    let protocol = match protocol_str {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        _ => return Err(SuruleParseError::InvalidProtocol(protocol_str.to_string()).into()),
    };

    Ok((input, protocol))
}

/// 从字符流中解析 IpAddrress List
pub(crate) fn parse_list_from_stream<L>(input: &str) -> IResult<&str, L, SuruleParseError>
where
    L: SurList + Default,
{
    // closures
    let make_err = |reason| SuruleParseError::InvalidList(reason).into();
    let push_element = |e_vec: &mut Option<Vec<L::Element>>, e: L::Element| {
        if let Some(v) = e_vec {
            v.push(e);
        } else {
            *e_vec = Some(vec![e]);
        }
    };

    // preprocess
    let input = handle_stream(input).map_err(|_| make_err("empty stream.".to_string()))?;
    let (input, list_string) = take_list_maybe_from_stream(input)
        .map(|(input, list_str)| (input, strip_quotes(list_str)))?;
    let mut list_str = list_string.as_str();

    // parse list
    let mut rst_list = L::default();
    if list_str == "any" || list_str == "all" || list_str == "$HTTP_PORTS" {
        // Warning: 目前尚不支持配置文件，所以替换了 `$HTTP_PORTS`
        return Ok((input, rst_list));
    } else if list_str.starts_with('!') {
        // exception: !...
        list_str = &list_str[1..];

        if list_str.starts_with('[') && list_str.ends_with(']') {
            // exception list: ![..., ...]
            parse_inner_list(list_str, rst_list.get_expect_mut())?;
        } else {
            // single exception value: !1.1.1.1
            *rst_list.get_expect_mut() = Some(vec![L::Element::from_str(list_str)?]);
        }

        Ok((input, rst_list))
    } else {
        // acception: ...
        if list_str.starts_with('[') && list_str.ends_with(']') {
            // first list: [..., ...]
            for s in take_list_members(list_str)? {
                let s = handle_value(s).map_err(|_| make_err("empty list value.".to_string()))?;
                if s.starts_with('!') {
                    // exception element: [!...]
                    let s = &s[1..];
                    if s.starts_with('[') && s.ends_with(']') {
                        // exception list: [![..., ...]]
                        parse_inner_list(s, rst_list.get_expect_mut())?;
                    } else {
                        // exception single value: [!1.1.1.1]
                        let element = L::Element::from_str(s)?;
                        push_element(rst_list.get_expect_mut(), element);
                    }
                } else {
                    // acception element: [...]
                    if s.starts_with('[') && s.ends_with(']') {
                        // acception list: [[..., ...]]
                        parse_inner_list(s, rst_list.get_accept_mut())?;
                    } else {
                        // acception single value: [1.1.1.1]
                        let element = L::Element::from_str(s)?;
                        push_element(rst_list.get_accept_mut(), element);
                    }
                }
            }
        } else {
            // single value: 1.1.1.1
            *rst_list.get_accept_mut() = Some(vec![L::Element::from_str(list_str)?]);
        }

        Ok((input, rst_list))
    }
}

/// 从字符流中解析 Direction
pub(crate) fn parse_direction_from_stream(
    input: &str,
) -> IResult<&str, Direction, SuruleParseError> {
    let make_err = |reason| SuruleParseError::InvalidDirection(reason).into();

    let input = handle_stream(input).map_err(|_| make_err("empty stream.".to_string()))?;
    if let Ok((input, direction)) = nom::branch::alt::<_, _, nom::error::Error<&str>, _>((
        nom::bytes::complete::tag("->"),
        nom::bytes::complete::tag("<>"),
    ))(input)
    {
        match direction {
            "->" => Ok((input, Direction::Uni)),
            "<>" => Ok((input, Direction::Bi)),
            _ => Err(make_err(direction.to_string())),
        }
    } else {
        Err(make_err(input.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use ipnet::Ipv4Net;

    use super::*;

    #[test]
    fn test_take_list_str() {
        // Ok
        assert_eq!(take_list_maybe_from_stream("[]"), Ok(("", "[]")));
        assert_eq!(
            take_list_maybe_from_stream("[1,[1,2],[1,2,3]]a"),
            Ok(("a", "[1,[1,2],[1,2,3]]"))
        );
        assert_eq!(
            take_list_maybe_from_stream(" [[hel]lo]a\r\n"),
            Ok(("a\r\n", "[[hel]lo]"))
        );
        assert_eq!(
            take_list_maybe_from_stream("aaa bbb ccc"),
            Ok((" bbb ccc", "aaa"))
        );
        // Err
        assert_eq!(
            take_list_maybe_from_stream(""),
            Err(SuruleParseError::EmptyStr.into())
        );
        assert_eq!(
            take_list_maybe_from_stream("\r"),
            Err(SuruleParseError::EmptyStr.into())
        );
        assert_eq!(
            take_list_maybe_from_stream("[[1,2]"),
            Err(SuruleParseError::UnterminatedList.into())
        );
    }

    #[test]
    fn test_action() {
        assert_eq!(
            parse_action_from_stream("alert\n \t xxx"),
            Ok(("\n \t xxx", Action::Alert))
        );
        assert_eq!(
            parse_action_from_stream("\t    pass xxx"),
            Ok((" xxx", Action::Pass))
        );
        assert_eq!(
            parse_action_from_stream("\n    drop xxx"),
            Ok((" xxx", Action::Drop))
        );
        assert_eq!(
            parse_action_from_stream("\r  reject xxx"),
            Ok((" xxx", Action::Reject))
        );
        assert_eq!(
            parse_action_from_stream(" rejectsrc xxx"),
            Ok((" xxx", Action::RejectSrc))
        );
        assert_eq!(
            parse_action_from_stream(" rejectdst xxx"),
            Ok((" xxx", Action::RejectDst))
        );
        assert_eq!(
            parse_action_from_stream("rejectboth xxx"),
            Ok((" xxx", Action::RejectBoth))
        );
    }

    #[test]
    fn test_protocol() {
        assert_eq!(
            parse_protocol_from_stream(" tcp xxx"),
            Ok((" xxx", Protocol::Tcp))
        );
        assert_eq!(
            parse_protocol_from_stream(" udp xxx"),
            Ok((" xxx", Protocol::Udp))
        );
    }

    #[test]
    fn test_ip_list() {
        assert_eq!(
            parse_list_from_stream(r#"any xxx"#),
            Ok((
                " xxx",
                IpAddressList {
                    accept: None,
                    except: None
                }
            ))
        );

        assert_eq!(
            parse_list_from_stream(r#" !["10.0.0.0/8", "192.168.0.1"] xxx"#),
            Ok((
                " xxx",
                IpAddressList {
                    accept: None,
                    except: Some(vec![
                        IpAddress::V4Range(Ipv4Net::from_str("10.0.0.0/8").unwrap()),
                        IpAddress::V4Addr(Ipv4Addr::from_str("192.168.0.1").unwrap())
                    ])
                }
            ))
        );

        // 使用示例
        let (_, rst) = parse_list_from_stream::<IpAddressList>(
            r#" ["10.0.0.0/8", !["10.0.0.1", "10.0.0.2"]] xxx"#,
        )
        .unwrap();
        let test_ip = Ipv4Addr::from_str("10.0.0.2").unwrap();
        if let Some(a) = rst.except {
            for ia in a {
                match ia {
                    IpAddress::V4Addr(addr) => {
                        if addr == test_ip {
                            // do sth.
                            return;
                        }
                    }
                    IpAddress::V4Range(range) => {
                        if range.contains(&test_ip) {
                            // do sth.
                            return;
                        }
                    }
                }
            }
            assert!(false)
        }
    }

    #[test]
    fn test_port_list() {
        assert_eq!(
            parse_list_from_stream("[80, 81, 82] xxx"),
            Ok((
                " xxx",
                PortList {
                    accept: Some(vec![Port::Single(80), Port::Single(81), Port::Single(82),]),
                    except: None
                }
            ))
        );

        assert_eq!(
            parse_list_from_stream(" [80: 82] xxx"),
            Ok((
                " xxx",
                PortList {
                    accept: Some(vec![Port::new_range(80, 82).unwrap(),]),
                    except: None
                }
            ))
        );

        assert_eq!(
            parse_list_from_stream("[1024:] xxx"),
            Ok((
                " xxx",
                PortList {
                    accept: Some(vec![Port::new_range(1024, u16::MAX).unwrap(),]),
                    except: None
                }
            ))
        );

        assert_eq!(
            parse_list_from_stream(" !80 xxx"),
            Ok((
                " xxx",
                PortList {
                    accept: None,
                    except: Some(vec![Port::Single(80)])
                }
            ))
        );

        assert_eq!(
            parse_list_from_stream(" [80:100,![86,87]] xxx"),
            Ok((
                " xxx",
                PortList {
                    accept: Some(vec![Port::new_range(80, 100).unwrap()]),
                    except: Some(vec![Port::Single(86), Port::Single(87)])
                }
            ))
        )
    }

    #[test]
    fn test_direction() {
        // Ok
        assert_eq!(parse_direction_from_stream("->"), Ok(("", Direction::Uni)));
        assert_eq!(parse_direction_from_stream("<>"), Ok(("", Direction::Bi)));
        assert_eq!(
            parse_direction_from_stream(" <>a\n"),
            Ok(("a\n", Direction::Bi))
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
}
