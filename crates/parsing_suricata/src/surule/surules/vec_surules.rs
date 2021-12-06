use tracing::{debug, error};

use crate::{
    surule::{TcpSurule, UdpSurule},
    SuruleParseError, Surule
};
use super::Surules;
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
                return Err(SuruleParseError::FilepathError(filepath.to_string()))
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
                Surule::Udp(udp_surule) => vec_surules.udp_rules.push(udp_surule)
            };
        }

        Ok(vec_surules)
    }
}


#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use ipnet::Ipv4Net;

    use crate::surule::InnerSurule;
    use crate::surule::elements::*;
    use crate::surule::SuruleOption;
    use super::*;

    #[test]
    fn test_parse_suricata_rule_from_file() {
        let vec_surules = VecSurules::parse_from_file("../../examples/suricata.rules").unwrap();
        assert_eq!(
            vec_surules,
            VecSurules {
                tcp_rules: vec![
                    TcpSurule::new(
                        Action::Alert,
                        IpAddressList {
                            accept: Some(vec![
                                IpAddress::V4Range(Ipv4Net::from_str("192.168.0.0/16").unwrap()),
                            ]),
                            except: Some(vec![
                                IpAddress::V4Addr(Ipv4Addr::from_str("192.168.0.3").unwrap())
                            ])
                        },
                        PortList {
                            accept: None,
                            except: None
                        },
                        Direction::Uni,
                        IpAddressList {
                            accept: Some(vec![
                                IpAddress::V4Addr(Ipv4Addr::from_str("192.168.0.110").unwrap())
                            ]),
                            except: None
                        },
                        PortList {
                            accept: Some(vec![
                                Port::Single(445),
                                Port::Single(3389),
                            ]),
                            except: None
                        },
                        vec![
                            SuruleOption::Message(
                                "ET DOS NetrWkstaUserEnum Request with large Preferred Max Len".to_string()
                            ),
                            SuruleOption::Flow("established,to_server".to_string()),
                            SuruleOption::Content(Content {
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
                            SuruleOption::Content(Content {
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
                            SuruleOption::Distance(Distance(CountOrName::Value(0))),
                            SuruleOption::Content(Content {
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
                            SuruleOption::Distance(Distance(CountOrName::Value(14))),
                            SuruleOption::Within(Within(CountOrName::Value(2))),
                            SuruleOption::ByteJump(ByteJump {
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
                            SuruleOption::Content(Content {
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
                            SuruleOption::Distance(Distance(CountOrName::Value(12))),
                            SuruleOption::Within(Within(CountOrName::Value(8))),
                            SuruleOption::GenericOption(GenericOption {
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
                ],
                udp_rules: vec![
                    UdpSurule::new(
                        Action::Alert,
                        IpAddressList {
                            accept: None,
                            except: None
                        },
                        PortList {
                            accept: None,
                            except: None
                        },
                        Direction::Bi,
                        IpAddressList {
                            accept: None,
                            except: Some(vec![
                                IpAddress::V4Addr(Ipv4Addr::from_str("192.168.0.110").unwrap()),
                                IpAddress::V4Addr(Ipv4Addr::from_str("192.168.0.111").unwrap()),
                                IpAddress::V4Addr(Ipv4Addr::from_str("192.168.0.112").unwrap())
                            ])
                        },
                        PortList {
                            accept: None,
                            except: None
                        },
                        vec![SuruleOption::Message("foo".to_string())]
                    )
                ]
            }
        )
    }
}
