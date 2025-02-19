use tracing::{error, trace};

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
    fn init_from_file(filepath: &str) -> Result<Self, SuruleParseError>
    where
        Self: Sized,
    {
        // read rules from file
        trace!("reading suricata rules file from: {}.", filepath);
        let file_string = match fs::read_to_string(filepath) {
            Ok(o) => o,
            Err(e) => {
                error!(error = %e, "error occurs while reading rule file.");
                return Err(SuruleParseError::FilepathError(filepath.to_string()));
            }
        };

        // convert string to VecSurules
        let mut vec_surules = VecSurules::default();
        for (i, rule_line) in file_string.lines().enumerate() {
            trace!("get No.{} suricata rule: `{}`.", i, rule_line);
            let surule = Surule::from_str(rule_line)
                .map_err(|e| {
                    error!(error = %e, "Suricata rules pasing error occurs at '{}' line{}.", filepath, i);
                    return e;
                })?;
            match surule {
                Surule::Tcp(tcp_surule) => vec_surules.tcp_rules.push(tcp_surule),
                Surule::Udp(udp_surule) => vec_surules.udp_rules.push(udp_surule),
            };
        }

        Ok(vec_surules)
    }

    fn load_from_file(&mut self, filepath: &str) -> Result<(), SuruleParseError>
    where
        Self: Sized,
    {
        // read rules from file
        trace!("reading suricata rules from: {}.", filepath);
        let file_string = match fs::read_to_string(filepath) {
            Ok(o) => o,
            Err(e) => {
                error!(error = %e, "error occurs while reading rule file.");
                return Err(SuruleParseError::FilepathError(filepath.to_string()));
            }
        };

        // convert string to VecSurules
        for (i, rule_line) in file_string.lines().enumerate() {
            trace!("get No.{} suricata rule: `{}`.", i, rule_line);
            let surule = Surule::from_str(rule_line)
                .map_err(|e| {
                    error!(error = %e, "Suricata rules pasing error occurs at '{}' line{}.", filepath, i);
                    return e;
                })?;
            match surule {
                Surule::Tcp(tcp_surule) => self.tcp_rules.push(tcp_surule),
                Surule::Udp(udp_surule) => self.udp_rules.push(udp_surule),
            };
        }

        Ok(())
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
    fn test_init_suricata_rules_from_file() {
        let vec_surules = VecSurules::init_from_file("./tests/unitest_suricata.rules").unwrap();
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
                    sid: 2003236,
                    meta_options: vec![
                        SuruleMetaOption::Message(
                            "ET DOS NetrWkstaUserEnum Request with large Preferred Max Len"
                                .to_string()
                        ),
                        SuruleMetaOption::Reference("cve,2006-6723".to_string()),
                        SuruleMetaOption::Reference(
                            "url,doc.emergingthreats.net/bin/view/Main/2003236".to_string()
                        ),
                        SuruleMetaOption::Classtype("attempted-dos".to_string()),
                        SuruleMetaOption::Sid(2003236),
                        SuruleMetaOption::Rev(4),
                        SuruleMetaOption::Metadata(vec![
                            "created_at 2010_07_30".to_string(), 
                            "updated_at 2010_07_30".to_string()
                        ])
                    ],
                    payload_options: vec![
                        SurulePayloadOption::Content(Content {
                            pattern: vec![255, 115, 109, 98],
                            fast_pattern: false,
                            nocase: true,
                            pos_key: ContentPosKey::NotSet
                        }),
                        SurulePayloadOption::Content(Content {
                            pattern: vec![16, 0, 0, 0],
                            fast_pattern: false,
                            nocase: false,
                            pos_key: ContentPosKey::Relative {
                                within: None,
                                distance: Some(0)
                            }
                        }),
                        SurulePayloadOption::Content(Content {
                            pattern: vec![2, 0],
                            fast_pattern: false,
                            nocase: false,
                            pos_key: ContentPosKey::Relative {
                                within: Some(2),
                                distance: Some(14)
                            }
                        }),
                        SurulePayloadOption::ByteJump(ByteJump {
                            count: 4,
                            offset: 12,
                            relative: true,
                            multiplier: Some(2),
                            endian: Some(Endian::Little),
                            string: false,
                            num_type: None,
                            align: false,
                            from: None,
                            post_offset: None,
                            dce: false,
                            bitmask: None
                        }),
                        SurulePayloadOption::Content(Content {
                            pattern: vec![0, 0, 0, 0, 0, 0, 0, 0],
                            fast_pattern: false,
                            nocase: false,
                            pos_key: ContentPosKey::Relative {
                                within: Some(8),
                                distance: Some(12)
                            }
                        }),
                        SurulePayloadOption::ByteTest(ByteTest {
                            count: 4,
                            op_nagation: false,
                            operator: ByteTestOp::Greater,
                            test_value: 2,
                            offset: 0,
                            relative: true,
                            ..Default::default()
                        }),
                        SurulePayloadOption::Pcre(
                            Pcre {
                                negate: false,
                                pattern: r#"<OBJECT\s+[^>]*classid\s*=\s*[\x22\x27]?\s*clsid\s*\x3a\s*\x7B?\s*BD9E5104-2F20"#.to_string(),
                                modifier_s: true,
                                modifier_i: true,
                                ..Default::default()
                            }
                        )
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
                    sid: 2003237,
                    meta_options: vec![
                        SuruleMetaOption::Message("foo".to_string()),
                        SuruleMetaOption::Sid(2003237)
                    ],
                    payload_options: vec![],
                    flow_options: vec![],
                    udp_options: vec![]
                }]
            }
        )
    }
}
