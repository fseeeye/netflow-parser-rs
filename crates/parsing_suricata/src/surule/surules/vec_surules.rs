use tracing::{debug, error};

use super::Surules;
use crate::{
    surule::{TcpSurule, UdpSurule},
    Surule, SuruleParseError,
};
use std::{fs, str::FromStr};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct VecSurules {
    pub tcp_rules: Vec<TcpSurule>,
    pub udp_rules: Vec<UdpSurule>,
}

impl Surules for VecSurules {
    fn parse_from_file(filepath: &str) -> Result<Self, SuruleParseError>
    where
        Self: Sized,
    {
        // read rules from file
        debug!(target: "SURICATA(VecSurules::parse_from_file)", "reading suricata rules file from: {}.", filepath);
        let file_string = match fs::read_to_string(filepath) {
            Ok(o) => o,
            Err(e) => {
                error!(target: "SURICATA(VecSurules::parse_from_file)", error = %e, "error occurs while reading rule file.");
                return Err(SuruleParseError::FilepathError(filepath.to_string()));
            }
        };

        // convert string to VecSurules
        let mut vec_surules = VecSurules::default();
        for (i, rule_line) in file_string.lines().enumerate() {
            debug!(target: "SURICATA(VecSurules::parse_from_file)", "get No.{} suricata rule: `{}`.", i, rule_line);
            let surule = Surule::from_str(rule_line)
                .map_err(|e| {
                    error!(target: "SURICATA(VecSurules::parse_from_file)", error = %e, "Suricata rules pasing error occurs at '{}' line{}.", filepath, i);
                    return e;
                })?;
            match surule {
                Surule::Tcp(tcp_surule) => vec_surules.tcp_rules.push(tcp_surule),
                Surule::Udp(udp_surule) => vec_surules.udp_rules.push(udp_surule),
            };
        }

        Ok(vec_surules)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use ipnet::Ipv4Net;

    use super::*;
    use crate::surule::elements::*;
    use crate::surule::option::SuruleFlowOption;
    use crate::surule::option::SuruleMetaOption;
    use crate::surule::option::SurulePayloadOption;

    #[test]
    fn test_parse_suricata_rule_from_file() {
        let vec_surules =
            VecSurules::parse_from_file("../../examples/test_suricata.rules").unwrap();
        assert_eq!(
            vec_surules,
            VecSurules {
                tcp_rules: vec![TcpSurule {
                    action: Action::Alert,
                    src_addr: IpAddressList {
                        accept: Some(vec![IpAddress::V4Range(
                            Ipv4Net::from_str("192.168.0.0/16").unwrap()
                        ),]),
                        except: Some(vec![IpAddress::V4Addr(
                            Ipv4Addr::from_str("192.168.0.3").unwrap()
                        )])
                    },
                    src_port: PortList {
                        accept: None,
                        except: None
                    },
                    direction: Direction::Uni,
                    dst_addr: IpAddressList {
                        accept: Some(vec![IpAddress::V4Addr(
                            Ipv4Addr::from_str("192.168.0.110").unwrap()
                        )]),
                        except: None
                    },
                    dst_port: PortList {
                        accept: Some(vec![Port::Single(445), Port::Single(3389),]),
                        except: None
                    },
                    meta_options: vec![
                        SuruleMetaOption::Message(
                            "ET DOS NetrWkstaUserEnum Request with large Preferred Max Len"
                                .to_string()
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
                    flow_options: vec![SuruleFlowOption::Flow(Flow(vec![
                        FlowMatcher::Established,
                        FlowMatcher::ToServer
                    ])),],
                    tcp_options: vec![]
                }],
                udp_rules: vec![UdpSurule {
                    action: Action::Alert,
                    src_addr: IpAddressList {
                        accept: None,
                        except: None
                    },
                    src_port: PortList {
                        accept: None,
                        except: None
                    },
                    direction: Direction::Bi,
                    dst_addr: IpAddressList {
                        accept: None,
                        except: Some(vec![
                            IpAddress::V4Addr(Ipv4Addr::from_str("192.168.0.110").unwrap()),
                            IpAddress::V4Addr(Ipv4Addr::from_str("192.168.0.111").unwrap()),
                            IpAddress::V4Addr(Ipv4Addr::from_str("192.168.0.112").unwrap())
                        ])
                    },
                    dst_port: PortList {
                        accept: None,
                        except: None
                    },
                    meta_options: vec![SuruleMetaOption::Message("foo".to_string())],
                    payload_options: vec![],
                    flow_options: vec![],
                    udp_options: vec![]
                }]
            }
        )
    }
}
