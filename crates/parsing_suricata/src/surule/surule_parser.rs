use nom::IResult;

use std::fs;

use super::{
    // mods
    types::{self, Action}, utils,
    // structs
    Surule, SuruleElement, error::SuruleParseError,
    // funcs
    element_parser
};


/// 从字符流中取出 含值可选元素 的值字符串
///
/// 该函数获得 ':' 后面的所有字符(input)，随后将第一个 ';' 前后的所有字符分为两组返回，
/// 不包含第一个 ';'。
fn take_option_value(input: &str) -> IResult<&str, &str, SuruleParseError<&str>> {
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
fn take_option_name(input: &str) -> IResult<&str, (&str, char), SuruleParseError<&str>> {
    // let (input, (name_str, sep)) = nom::sequence::tuple((
    //     nom::sequence::preceded(
    //         nom::character::complete::multispace0,
    //         nom::bytes::complete::is_not(":;")
    //     ),
    //     nom::character::complete::one_of(":;")
    // ))(input)?;
    // let name_str = name_str.trim_end();
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

/// 从字符流中，解析一个可选字段元素
fn parse_option_element(input: &str) -> IResult<&str, SuruleElement, SuruleParseError<&str>> {
    let (input, (name_str, sep)) = take_option_name(input)?;
    if sep == ';' {
        // name_str 是不含值的 option 字段
        Ok((input, name_str.into()))
    } else {
        // name_str 是含值的 option 字段
        let (input, value_str) = take_option_value(input)?;
        let surule_element = match name_str {
            "byte_jump" => SuruleElement::ByteJump(element_parser::parse_byte_jump(value_str)?),
            "classtype" => SuruleElement::Classtype(value_str.to_owned()),
            "content" => SuruleElement::Content(types::Content::new(value_str.to_owned())),
            "depth" => SuruleElement::Depth(element_parser::parse_u64(value_str, "depth")?),
            "distance" => SuruleElement::Distance(types::Distance(
                element_parser::parse_count_or_name(value_str)?,
            )),
            "within" => SuruleElement::Within(types::Within(element_parser::parse_count_or_name(
                value_str,
            )?)),
            "dsize" => SuruleElement::Dsize(value_str.to_owned()),
            "flow" => SuruleElement::Flow(value_str.to_owned()),
            "flowbits" => SuruleElement::Flowbits(element_parser::parse_flowbits(value_str)?),
            "isdataat" => SuruleElement::IsDataAt(value_str.to_owned()),
            "metadata" => SuruleElement::Metadata(value_str.to_owned()),
            "msg" => SuruleElement::Message(utils::strip_quotes(value_str)),
            "offset" => SuruleElement::Offset(element_parser::parse_u64(value_str, "offset")?),
            "pcre" => SuruleElement::Pcre(value_str.to_owned()),
            "reference" => SuruleElement::Reference(value_str.to_owned()),
            "rev" => SuruleElement::Rev(element_parser::parse_u64(value_str, "rev")?),
            "sid" => SuruleElement::Sid(element_parser::parse_u64(value_str, "sid")?),
            _ => SuruleElement::GenericOption(types::GenericOption {
                name: name_str.to_string(),
                val: Some(value_str.to_string()),
            }),
        };
        Ok((input, surule_element))
    }
}

pub fn parse_surule_from_file(filepath: &str) -> Option<Surule>  {
    let rule_str = match fs::read_to_string(filepath) {
        Ok(o) => o,
        Err(e) => {
            println!("encountered io error while reading surule file: {:?}", e);
            return None;
        }
    };

    match parse_surule(&rule_str) {
        Ok((_remain, surule)) => Some(surule),
        Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => {
            println!("{}", e);
            None
        },
        Err(nom::Err::Incomplete(_)) => {
            println!("encountered unknow error: nom incomplete.");
            None
        }
    }
}

/// 解析 Suricata Rule 字符串 -> Surule 结构体
pub fn parse_surule(input: &str) -> IResult<&str, Surule, SuruleParseError<&str>> {
    // parse header elements
    let (input, (action, protocol, src_addr, src_port, direction, dst_addr, dst_port)): (
        &str,
        (Action, types::Protocol, types::IpAddressList, types::PortList, types::Direction, types::IpAddressList, types::PortList),
    ) = nom::sequence::tuple((
        element_parser::parse_action_from_stream,
        element_parser::parse_protocol_from_stream,
        element_parser::parse_list_from_stream,
        element_parser::parse_list_from_stream,
        element_parser::parse_direction_from_stream,
        element_parser::parse_list_from_stream,
        element_parser::parse_list_from_stream,
    ))(input)?;

    // parse option elements
    let (input, _start_backet) =
        nom::bytes::complete::tag::<_, _, nom::error::Error<&str>>("(")(input.trim_start())
            .map_err(|_| nom::Err::Error(SuruleParseError::NoOptionElement))?;
    let mut options = Vec::new();

    let mut input = input;
    loop {
        if let Ok((rem, _close_backet)) =
            nom::bytes::complete::tag::<_, _, nom::error::Error<&str>>(")")(input.trim_start())
        {
            input = rem;
            break;
        }
        let (rem, option) = parse_option_element(input)?;
        options.push(option);
        input = rem;
    }

    Ok((
        input,
        Surule::new(
            action, protocol, src_addr, src_port, direction, dst_addr, dst_port, options,
        ),
    ))
}


#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::vec;
    use std::str::FromStr;

    use ipnet::Ipv4Net;
    use parsing_parser::TransportProtocol;

    use super::*;

    #[test]
    pub fn test_parse_suricata_rule() {
        let input = r#"alert tcp ["192.168.0.0/16", !"192.168.0.3"] any -> "192.168.0.110" [445,3389] (
            msg:"ET DOS NetrWkstaUserEnum Request with large Preferred Max Len";
            flow:established,to_server; 
            content:"|ff|SMB"; content:"|10 00 00 00|";
            distance:0; content:"|02 00|";
            distance:14;
            within:2;
            byte_jump:4,12,relative,little,multiplier 2;
            content:"|00 00 00 00 00 00 00 00|";
            distance:12;
            within:8;
            byte_test:4,>,2,0,relative;
            reference:cve,2006-6723;
            reference:url,doc.emergingthreats.net/bin/view/Main/2003236;
            classtype:attempted-dos;
            sid:2003236;
            rev:4;
            metadata:created_at 2010_07_30, updated_at 2010_07_30;)"#;
        let (remaining_input, suricata_rule) = parse_surule(input).unwrap();
        assert_eq!(remaining_input, "");
        assert_eq!(
            suricata_rule,
            Surule::new(
                Action::Alert,
                types::Protocol::Transport(TransportProtocol::Tcp),
                types::IpAddressList {
                    accept: Some(vec![
                        types::IpAddress::V4Range(Ipv4Net::from_str("192.168.0.0/16").unwrap()),
                    ]),
                    except: Some(vec![
                        types::IpAddress::V4Addr(Ipv4Addr::from_str("192.168.0.3").unwrap())
                    ])
                },
                types::PortList {
                    accept: None,
                    except: None
                },
                types::Direction::Uni,
                types::IpAddressList {
                    accept: Some(vec![
                        types::IpAddress::V4Addr(Ipv4Addr::from_str("192.168.0.110").unwrap())
                    ]),
                    except: None
                },
                types::PortList {
                    accept: Some(vec![
                        types::Port::Single(445),
                        types::Port::Single(3389),
                    ]),
                    except: None
                },
                vec![
                    SuruleElement::Message(
                        "ET DOS NetrWkstaUserEnum Request with large Preferred Max Len".to_string()
                    ),
                    SuruleElement::Flow("established,to_server".to_string()),
                    SuruleElement::Content(types::Content {
                        pattern: "\"|ff|SMB\"".to_string(),
                        depth: 0,
                        distance: types::Distance(types::CountOrName::Value(0)),
                        endswith: false,
                        fast_pattern: false,
                        nocase: false,
                        offset: 0,
                        startswith: false,
                        within: types::Within(types::CountOrName::Value(0))
                    }),
                    SuruleElement::Content(types::Content {
                        pattern: "\"|10 00 00 00|\"".to_string(),
                        depth: 0,
                        distance: types::Distance(types::CountOrName::Value(0)),
                        endswith: false,
                        fast_pattern: false,
                        nocase: false,
                        offset: 0,
                        startswith: false,
                        within: types::Within(types::CountOrName::Value(0))
                    }),
                    SuruleElement::Distance(types::Distance(types::CountOrName::Value(0))),
                    SuruleElement::Content(types::Content {
                        pattern: "\"|02 00|\"".to_string(),
                        depth: 0,
                        distance: types::Distance(types::CountOrName::Value(0)),
                        endswith: false,
                        fast_pattern: false,
                        nocase: false,
                        offset: 0,
                        startswith: false,
                        within: types::Within(types::CountOrName::Value(0))
                    }),
                    SuruleElement::Distance(types::Distance(types::CountOrName::Value(14))),
                    SuruleElement::Within(types::Within(types::CountOrName::Value(2))),
                    SuruleElement::ByteJump(types::ByteJump {
                        count: 4,
                        offset: 12,
                        relative: true,
                        multiplier: 2,
                        endian: types::Endian::Little,
                        string: false,
                        hex: false,
                        dec: false,
                        oct: false,
                        align: false,
                        from_beginning: false,
                        from_end: false,
                        post_offset: 0,
                        dce: false,
                        bitmask: 0
                    }),
                    SuruleElement::Content(types::Content {
                        pattern: "\"|00 00 00 00 00 00 00 00|\"".to_string(),
                        depth: 0,
                        distance: types::Distance(types::CountOrName::Value(0)),
                        endswith: false,
                        fast_pattern: false,
                        nocase: false,
                        offset: 0,
                        startswith: false,
                        within: types::Within(types::CountOrName::Value(0))
                    }),
                    SuruleElement::Distance(types::Distance(types::CountOrName::Value(12))),
                    SuruleElement::Within(types::Within(types::CountOrName::Value(8))),
                    SuruleElement::GenericOption(types::GenericOption {
                        name: "byte_test".to_string(),
                        val: Some("4,>,2,0,relative".to_string())
                    }),
                    SuruleElement::Reference("cve,2006-6723".to_string()),
                    SuruleElement::Reference(
                        "url,doc.emergingthreats.net/bin/view/Main/2003236".to_string()
                    ),
                    SuruleElement::Classtype("attempted-dos".to_string()),
                    SuruleElement::Sid(2003236),
                    SuruleElement::Rev(4),
                    SuruleElement::Metadata(
                        "created_at 2010_07_30, updated_at 2010_07_30".to_string()
                    )
                ]
            )
        );
    }

    #[test]
    pub fn test_parse_suricata_rule_file() {
        let surule = parse_surule_from_file("../../examples/suricata3.rule").unwrap();
        assert_eq!(
            surule, 
            Surule::new(
                Action::Alert,
                types::Protocol::Transport(TransportProtocol::Tcp),
                types::IpAddressList {
                    accept: Some(vec![
                        types::IpAddress::V4Range(Ipv4Net::from_str("192.168.0.0/16").unwrap()),
                    ]),
                    except: Some(vec![
                        types::IpAddress::V4Addr(Ipv4Addr::from_str("192.168.0.3").unwrap())
                    ])
                },
                types::PortList {
                    accept: None,
                    except: None
                },
                types::Direction::Uni,
                types::IpAddressList {
                    accept: Some(vec![
                        types::IpAddress::V4Addr(Ipv4Addr::from_str("192.168.0.110").unwrap())
                    ]),
                    except: None
                },
                types::PortList {
                    accept: Some(vec![
                        types::Port::Single(445),
                        types::Port::Single(3389),
                    ]),
                    except: None
                },
                vec![
                    SuruleElement::Message(
                        "ET DOS NetrWkstaUserEnum Request with large Preferred Max Len".to_string()
                    ),
                    SuruleElement::Flow("established,to_server".to_string()),
                    SuruleElement::Content(types::Content {
                        pattern: "\"|ff|SMB\"".to_string(),
                        depth: 0,
                        distance: types::Distance(types::CountOrName::Value(0)),
                        endswith: false,
                        fast_pattern: false,
                        nocase: false,
                        offset: 0,
                        startswith: false,
                        within: types::Within(types::CountOrName::Value(0))
                    }),
                    SuruleElement::Content(types::Content {
                        pattern: "\"|10 00 00 00|\"".to_string(),
                        depth: 0,
                        distance: types::Distance(types::CountOrName::Value(0)),
                        endswith: false,
                        fast_pattern: false,
                        nocase: false,
                        offset: 0,
                        startswith: false,
                        within: types::Within(types::CountOrName::Value(0))
                    }),
                    SuruleElement::Distance(types::Distance(types::CountOrName::Value(0))),
                    SuruleElement::Content(types::Content {
                        pattern: "\"|02 00|\"".to_string(),
                        depth: 0,
                        distance: types::Distance(types::CountOrName::Value(0)),
                        endswith: false,
                        fast_pattern: false,
                        nocase: false,
                        offset: 0,
                        startswith: false,
                        within: types::Within(types::CountOrName::Value(0))
                    }),
                    SuruleElement::Distance(types::Distance(types::CountOrName::Value(14))),
                    SuruleElement::Within(types::Within(types::CountOrName::Value(2))),
                    SuruleElement::ByteJump(types::ByteJump {
                        count: 4,
                        offset: 12,
                        relative: true,
                        multiplier: 2,
                        endian: types::Endian::Little,
                        string: false,
                        hex: false,
                        dec: false,
                        oct: false,
                        align: false,
                        from_beginning: false,
                        from_end: false,
                        post_offset: 0,
                        dce: false,
                        bitmask: 0
                    }),
                    SuruleElement::Content(types::Content {
                        pattern: "\"|00 00 00 00 00 00 00 00|\"".to_string(),
                        depth: 0,
                        distance: types::Distance(types::CountOrName::Value(0)),
                        endswith: false,
                        fast_pattern: false,
                        nocase: false,
                        offset: 0,
                        startswith: false,
                        within: types::Within(types::CountOrName::Value(0))
                    }),
                    SuruleElement::Distance(types::Distance(types::CountOrName::Value(12))),
                    SuruleElement::Within(types::Within(types::CountOrName::Value(8))),
                    SuruleElement::GenericOption(types::GenericOption {
                        name: "byte_test".to_string(),
                        val: Some("4,>,2,0,relative".to_string())
                    }),
                    SuruleElement::Reference("cve,2006-6723".to_string()),
                    SuruleElement::Reference(
                        "url,doc.emergingthreats.net/bin/view/Main/2003236".to_string()
                    ),
                    SuruleElement::Classtype("attempted-dos".to_string()),
                    SuruleElement::Sid(2003236),
                    SuruleElement::Rev(4),
                    SuruleElement::Metadata(
                        "created_at 2010_07_30, updated_at 2010_07_30".to_string()
                    )
                ]
            )
        )
    }
}
