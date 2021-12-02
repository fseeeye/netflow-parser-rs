use std::str::FromStr;

use super::{
    // mods
    elements,
    elements::Action,
    // funcs
    option::parse_option_element,
    // structs
    Surule,
    SuruleParseError,
};

impl FromStr for Surule {
    type Err = nom::Err<SuruleParseError>;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        // parse header elements
        let (input, (action, protocol, src_addr, src_port, direction, dst_addr, dst_port)): (
            &str,
            (
                Action,
                elements::Protocol,
                elements::IpAddressList,
                elements::PortList,
                elements::Direction,
                elements::IpAddressList,
                elements::PortList,
            ),
        ) = nom::sequence::tuple((
            elements::parse_action_from_stream,
            elements::parse_protocol_from_stream,
            elements::parse_list_from_stream,
            elements::parse_list_from_stream,
            elements::parse_direction_from_stream,
            elements::parse_list_from_stream,
            elements::parse_list_from_stream,
        ))(input)
        .map_err(|e| SuruleParseError::HeaderError(format!("{}", e)).into())?;

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
            let (rem, option) = parse_option_element(input)?; // Warning: 后续优化中，需要根据协议采用不同的 parse_xxx_option_element 函数
            options.push(option);
            input = rem;
        }

        if input.len() != 0 {
            return Err(SuruleParseError::UnterminatedRule(input.to_string()).into());
        }

        Ok(Surule::new(
            action, protocol, src_addr, src_port, direction, dst_addr, dst_port, options,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::vec;

    use ipnet::Ipv4Net;

    use super::*;
    use crate::SuruleOption;

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
        let suricata_rule = Surule::from_str(input).unwrap();
        assert_eq!(
            suricata_rule,
            Surule::new(
                Action::Alert,
                elements::Protocol::Tcp,
                elements::IpAddressList {
                    accept: Some(vec![elements::IpAddress::V4Range(
                        Ipv4Net::from_str("192.168.0.0/16").unwrap()
                    ),]),
                    except: Some(vec![elements::IpAddress::V4Addr(
                        Ipv4Addr::from_str("192.168.0.3").unwrap()
                    )])
                },
                elements::PortList {
                    accept: None,
                    except: None
                },
                elements::Direction::Uni,
                elements::IpAddressList {
                    accept: Some(vec![elements::IpAddress::V4Addr(
                        Ipv4Addr::from_str("192.168.0.110").unwrap()
                    )]),
                    except: None
                },
                elements::PortList {
                    accept: Some(vec![
                        elements::Port::Single(445),
                        elements::Port::Single(3389),
                    ]),
                    except: None
                },
                vec![
                    SuruleOption::Message(
                        "ET DOS NetrWkstaUserEnum Request with large Preferred Max Len".to_string()
                    ),
                    SuruleOption::Flow("established,to_server".to_string()),
                    SuruleOption::Content(elements::Content {
                        pattern: "\"|ff|SMB\"".to_string(),
                        depth: 0,
                        distance: elements::Distance(elements::CountOrName::Value(0)),
                        endswith: false,
                        fast_pattern: false,
                        nocase: false,
                        offset: 0,
                        startswith: false,
                        within: elements::Within(elements::CountOrName::Value(0))
                    }),
                    SuruleOption::Content(elements::Content {
                        pattern: "\"|10 00 00 00|\"".to_string(),
                        depth: 0,
                        distance: elements::Distance(elements::CountOrName::Value(0)),
                        endswith: false,
                        fast_pattern: false,
                        nocase: false,
                        offset: 0,
                        startswith: false,
                        within: elements::Within(elements::CountOrName::Value(0))
                    }),
                    SuruleOption::Distance(elements::Distance(elements::CountOrName::Value(0))),
                    SuruleOption::Content(elements::Content {
                        pattern: "\"|02 00|\"".to_string(),
                        depth: 0,
                        distance: elements::Distance(elements::CountOrName::Value(0)),
                        endswith: false,
                        fast_pattern: false,
                        nocase: false,
                        offset: 0,
                        startswith: false,
                        within: elements::Within(elements::CountOrName::Value(0))
                    }),
                    SuruleOption::Distance(elements::Distance(elements::CountOrName::Value(14))),
                    SuruleOption::Within(elements::Within(elements::CountOrName::Value(2))),
                    SuruleOption::ByteJump(elements::ByteJump {
                        count: 4,
                        offset: 12,
                        relative: true,
                        multiplier: 2,
                        endian: elements::Endian::Little,
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
                    SuruleOption::Content(elements::Content {
                        pattern: "\"|00 00 00 00 00 00 00 00|\"".to_string(),
                        depth: 0,
                        distance: elements::Distance(elements::CountOrName::Value(0)),
                        endswith: false,
                        fast_pattern: false,
                        nocase: false,
                        offset: 0,
                        startswith: false,
                        within: elements::Within(elements::CountOrName::Value(0))
                    }),
                    SuruleOption::Distance(elements::Distance(elements::CountOrName::Value(12))),
                    SuruleOption::Within(elements::Within(elements::CountOrName::Value(8))),
                    SuruleOption::GenericOption(elements::GenericOption {
                        name: "byte_test".to_string(),
                        val: Some("4,>,2,0,relative".to_string())
                    }),
                    SuruleOption::Reference("cve,2006-6723".to_string()),
                    SuruleOption::Reference(
                        "url,doc.emergingthreats.net/bin/view/Main/2003236".to_string()
                    ),
                    SuruleOption::Classtype("attempted-dos".to_string()),
                    SuruleOption::Sid(2003236),
                    SuruleOption::Rev(4),
                    SuruleOption::Metadata(
                        "created_at 2010_07_30, updated_at 2010_07_30".to_string()
                    )
                ]
            )
        );
    }

    // TODO
    // #[test]
    // pub fn test_parse_suricata_rule_file() {
    //     let surule = parse_surule_from_file("../../examples/suricata3.rule").unwrap();
    //     assert_eq!(
    //         surule,
    //         Surule::new(
    //             Action::Alert,
    //             elements::Protocol::Tcp,
    //             elements::IpAddressList {
    //                 accept: Some(vec![
    //                     elements::IpAddress::V4Range(Ipv4Net::from_str("192.168.0.0/16").unwrap()),
    //                 ]),
    //                 except: Some(vec![
    //                     elements::IpAddress::V4Addr(Ipv4Addr::from_str("192.168.0.3").unwrap())
    //                 ])
    //             },
    //             elements::PortList {
    //                 accept: None,
    //                 except: None
    //             },
    //             elements::Direction::Uni,
    //             elements::IpAddressList {
    //                 accept: Some(vec![
    //                     elements::IpAddress::V4Addr(Ipv4Addr::from_str("192.168.0.110").unwrap())
    //                 ]),
    //                 except: None
    //             },
    //             elements::PortList {
    //                 accept: Some(vec![
    //                     elements::Port::Single(445),
    //                     elements::Port::Single(3389),
    //                 ]),
    //                 except: None
    //             },
    //             vec![
    //                 SuruleOption::Message(
    //                     "ET DOS NetrWkstaUserEnum Request with large Preferred Max Len".to_string()
    //                 ),
    //                 SuruleOption::Flow("established,to_server".to_string()),
    //                 SuruleOption::Content(elements::Content {
    //                     pattern: "\"|ff|SMB\"".to_string(),
    //                     depth: 0,
    //                     distance: elements::Distance(elements::CountOrName::Value(0)),
    //                     endswith: false,
    //                     fast_pattern: false,
    //                     nocase: false,
    //                     offset: 0,
    //                     startswith: false,
    //                     within: elements::Within(elements::CountOrName::Value(0))
    //                 }),
    //                 SuruleOption::Content(elements::Content {
    //                     pattern: "\"|10 00 00 00|\"".to_string(),
    //                     depth: 0,
    //                     distance: elements::Distance(elements::CountOrName::Value(0)),
    //                     endswith: false,
    //                     fast_pattern: false,
    //                     nocase: false,
    //                     offset: 0,
    //                     startswith: false,
    //                     within: elements::Within(elements::CountOrName::Value(0))
    //                 }),
    //                 SuruleOption::Distance(elements::Distance(elements::CountOrName::Value(0))),
    //                 SuruleOption::Content(elements::Content {
    //                     pattern: "\"|02 00|\"".to_string(),
    //                     depth: 0,
    //                     distance: elements::Distance(elements::CountOrName::Value(0)),
    //                     endswith: false,
    //                     fast_pattern: false,
    //                     nocase: false,
    //                     offset: 0,
    //                     startswith: false,
    //                     within: elements::Within(elements::CountOrName::Value(0))
    //                 }),
    //                 SuruleOption::Distance(elements::Distance(elements::CountOrName::Value(14))),
    //                 SuruleOption::Within(elements::Within(elements::CountOrName::Value(2))),
    //                 SuruleOption::ByteJump(elements::ByteJump {
    //                     count: 4,
    //                     offset: 12,
    //                     relative: true,
    //                     multiplier: 2,
    //                     endian: elements::Endian::Little,
    //                     string: false,
    //                     hex: false,
    //                     dec: false,
    //                     oct: false,
    //                     align: false,
    //                     from_beginning: false,
    //                     from_end: false,
    //                     post_offset: 0,
    //                     dce: false,
    //                     bitmask: 0
    //                 }),
    //                 SuruleOption::Content(elements::Content {
    //                     pattern: "\"|00 00 00 00 00 00 00 00|\"".to_string(),
    //                     depth: 0,
    //                     distance: elements::Distance(elements::CountOrName::Value(0)),
    //                     endswith: false,
    //                     fast_pattern: false,
    //                     nocase: false,
    //                     offset: 0,
    //                     startswith: false,
    //                     within: elements::Within(elements::CountOrName::Value(0))
    //                 }),
    //                 SuruleOption::Distance(elements::Distance(elements::CountOrName::Value(12))),
    //                 SuruleOption::Within(elements::Within(elements::CountOrName::Value(8))),
    //                 SuruleOption::GenericOption(elements::GenericOption {
    //                     name: "byte_test".to_string(),
    //                     val: Some("4,>,2,0,relative".to_string())
    //                 }),
    //                 SuruleOption::Reference("cve,2006-6723".to_string()),
    //                 SuruleOption::Reference(
    //                     "url,doc.emergingthreats.net/bin/view/Main/2003236".to_string()
    //                 ),
    //                 SuruleOption::Classtype("attempted-dos".to_string()),
    //                 SuruleOption::Sid(2003236),
    //                 SuruleOption::Rev(4),
    //                 SuruleOption::Metadata(
    //                     "created_at 2010_07_30, updated_at 2010_07_30".to_string()
    //                 )
    //             ]
    //         )
    //     )
    // }
}
