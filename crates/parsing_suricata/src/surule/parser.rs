use std::str::FromStr;

use super::{
    // mods
    elements,
    elements::Action,
    // funcs
    option::parse_option_from_stream,
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
            let (rem, option) = parse_option_from_stream(input)?; // Warning: 后续优化中，需要根据协议采用不同的 parse_xxx_option_element 函数
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

    use crate::surule::option::{SuruleMetaOption, SurulePayloadOption, SuruleFlowOption};
    use crate::surule::{elements::*, TcpSurule};
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
        let suricata_rule = Surule::from_str(input).unwrap();
        assert_eq!(
            suricata_rule,
            Surule::Tcp(TcpSurule {
                action: Action::Alert,
                src_addr: IpAddressList {
                    accept: Some(vec![
                        IpAddress::V4Range(Ipv4Net::from_str("192.168.0.0/16").unwrap()),
                    ]),
                    except: Some(vec![
                        IpAddress::V4Addr(Ipv4Addr::from_str("192.168.0.3").unwrap())
                    ])
                },
                src_port: PortList {
                    accept: None,
                    except: None
                },
                direction: Direction::Uni,
                dst_addr: IpAddressList {
                    accept: Some(vec![
                        IpAddress::V4Addr(Ipv4Addr::from_str("192.168.0.110").unwrap())
                    ]),
                    except: None
                },
                dst_port: PortList {
                    accept: Some(vec![
                        Port::Single(445),
                        Port::Single(3389),
                    ]),
                    except: None
                },
                meta_options: vec![
                    SuruleMetaOption::Message(
                        "ET DOS NetrWkstaUserEnum Request with large Preferred Max Len".to_string()
                    ),
                    // SuruleOption::GenericOption(GenericOption {
                    //     name: "byte_test".to_string(),
                    //     val: Some("4,>,2,0,relative".to_string())
                    // }),
                    SuruleMetaOption::Reference("cve,2006-6723".to_string()),
                    SuruleMetaOption::Reference(
                        "url,doc.emergingthreats.net/bin/view/Main/2003236".to_string()
                    ),
                    SuruleMetaOption::Classtype("attempted-dos".to_string()),
                    SuruleMetaOption::Sid(2003236),
                    SuruleMetaOption::Rev(4),
                    SuruleMetaOption::Metadata(
                        "created_at 2010_07_30, updated_at 2010_07_30".to_string()
                    )
                ],
                payload_options: vec![
                    SurulePayloadOption::Content(Content {
                        pattern: "\"|ff|SMB\"".to_string(),
                        depth: 0,
                        distance: Distance(CountOrName::Value(0)),
                        endswith: false,
                        fast_pattern: false,
                        nocase: false,
                        offset: 0,
                        startswith: false,
                        within: Within(CountOrName::Value(0))
                    }),
                    SurulePayloadOption::Content(Content {
                        pattern: "\"|10 00 00 00|\"".to_string(),
                        depth: 0,
                        distance: Distance(CountOrName::Value(0)),
                        endswith: false,
                        fast_pattern: false,
                        nocase: false,
                        offset: 0,
                        startswith: false,
                        within: Within(CountOrName::Value(0))
                    }),
                    SurulePayloadOption::Distance(Distance(CountOrName::Value(0))),
                    SurulePayloadOption::Content(Content {
                        pattern: "\"|02 00|\"".to_string(),
                        depth: 0,
                        distance: Distance(CountOrName::Value(0)),
                        endswith: false,
                        fast_pattern: false,
                        nocase: false,
                        offset: 0,
                        startswith: false,
                        within: Within(CountOrName::Value(0))
                    }),
                    SurulePayloadOption::Distance(Distance(CountOrName::Value(14))),
                    SurulePayloadOption::Within(Within(CountOrName::Value(2))),
                    SurulePayloadOption::ByteJump(ByteJump {
                        count: 4,
                        offset: 12,
                        relative: true,
                        multiplier: 2,
                        endian: Endian::Little,
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
                    SurulePayloadOption::Content(Content {
                        pattern: "\"|00 00 00 00 00 00 00 00|\"".to_string(),
                        depth: 0,
                        distance: Distance(CountOrName::Value(0)),
                        endswith: false,
                        fast_pattern: false,
                        nocase: false,
                        offset: 0,
                        startswith: false,
                        within: Within(CountOrName::Value(0))
                    }),
                    SurulePayloadOption::Distance(Distance(CountOrName::Value(12))),
                    SurulePayloadOption::Within(Within(CountOrName::Value(8))),
                ],
                flow_options: vec![
                    SuruleFlowOption::Flow(Flow(vec![
                        FlowMatcher::Established,
                        FlowMatcher::ToServer
                    ])),
                ],
                tcp_options: vec![]
            })
        );
    }
}
