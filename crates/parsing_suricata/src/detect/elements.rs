use lazy_static::lazy_static;
use tracing::error;

use std::{net::Ipv4Addr, collections::HashMap, sync::Mutex, ops::BitXorAssign};

use crate::surule::elements::{IpAddressList, PortList, SurList, Flowbits, FlowbitCommand};


pub trait SuruleElementDetector {
    type Comparison;
    fn check(&self, _: &Self::Comparison) -> bool;
}

pub trait SuruleElementSimpleDetector: SuruleElementDetector {
    fn check_simple(&self) -> bool;
}

/* Impl SuruleElementDetector for Header */

// 实现 PortList 的 check 接口
impl SuruleElementDetector for PortList {
    type Comparison = u16;
    #[inline]
    fn check(&self, compare_port_ref: &Self::Comparison) -> bool {
        let compare_port = *compare_port_ref;
        if self.check_accept(compare_port) {
            return !self.check_except(compare_port);
        } else {
            return false;
        }
    }
}

impl PortList {
    // 判断 port 是否存在于 accept ports 中
    #[inline]
    fn check_accept(&self, compare_port: u16) -> bool {
        if let Some(accept_ports) = self.get_accept() {
            for accept_port in accept_ports {
                if accept_port.contains(compare_port) {
                    // 如果 compare port 存在于 accept ports 中，返回 true
                    return true;
                }
            }
            // 如果 compare port 不存在于任何 accept ports 中，返回 false
            return false;
        } else {
            // accept = any，返回 true
            return true;
        }
    }

    // 判断 port 是否存在于 except ports 中
    #[inline]
    fn check_except(&self, compare_port: u16) -> bool {
        if let Some(except_ports) = self.get_expect() {
            for except_port in except_ports {
                if except_port.contains(compare_port) {
                    // 如果 compare port 存在于 except ports 中，返回 true
                    return true;
                }
            }
            // 如果 compare port 不存在于任何 except ports 中，返回 false
            return false;
        } else {
            // except = none，返回 false
            return false;
        }
    }
}

// 实现 IpAddressList 的 check 接口
impl SuruleElementDetector for IpAddressList {
    type Comparison = Ipv4Addr;

    fn check(&self, compare_ipv4: &Self::Comparison) -> bool {
        if self.check_accept(compare_ipv4) {
            return !self.check_except(compare_ipv4);
        } else {
            return false;
        }
    }
}

impl IpAddressList {
    // 判断 port 是否存在于 accept addresses 中
    #[inline]
    fn check_accept(&self, compare_ipv4: &Ipv4Addr) -> bool {
        if let Some(accept_addrs) = self.get_accept() {
            for accept_addr in accept_addrs {
                if accept_addr.contains(compare_ipv4) {
                    // 如果 compare addr 存在于 accept addrs 中，返回 true
                    return true;
                }
            }
            // 如果 compare addr 不存在于任何 accept addrs 中，返回 false
            return false;
        } else {
            // accept = any，返回 true
            return true;
        }
    }

    // 判断 port 是否存在于 except addresses 中
    #[inline]
    fn check_except(&self, compare_ipv4: &Ipv4Addr) -> bool {
        if let Some(except_addrs) = self.get_expect() {
            // 如果 compare addr 存在于 except addrs 中，返回 true
            for except_addr in except_addrs {
                if except_addr.contains(compare_ipv4) {
                    return true;
                }
            }
            // 如果 compare addr 不存在于任何 except addrs 中，返回 false
            return false;
        } else {
            // except = none，返回 false
            return false;
        }
    }
}


/* Impl SuruleElementDetector for Body */
// 实现 Flowbits 的 check 接口
impl SuruleElementDetector for Flowbits {
    type Comparison = bool;

    #[inline(always)]
    fn check(&self, _: &Self::Comparison) -> bool {
        check_flowbits(self)
    }
}

impl SuruleElementSimpleDetector for Flowbits {
    #[inline(always)]
    fn check_simple(&self) -> bool {
        check_flowbits(self)
    }
}

fn check_flowbits(flowbits: &Flowbits) -> bool {
    lazy_static! {
        static ref FLOWBITHASH: Mutex<HashMap<String, bool>> = Mutex::new(HashMap::new());
    }
    
    match flowbits.command {
        // 检查是否为 false
        FlowbitCommand::IsNotSet => {
            for name in &flowbits.names {
                match FLOWBITHASH.lock() {
                    Ok(flowbit_hashmap) => {
                        if let Some(v) = flowbit_hashmap.get(name) {
                            if *v == false {
                                continue
                            } else {
                                return false
                            }
                        } else {
                            continue;
                        }
                    },
                    Err(e) => {
                        error!(target: "SURICATA(Flowbits::check)", error = %e)
                    }
                }
            }
            true
        },
        // 检查是否为 true
        FlowbitCommand::IsSet => {
            for name in &flowbits.names {
                match FLOWBITHASH.lock() {
                    Ok(flowbit_hashmap) => {
                        if let Some(v) = flowbit_hashmap.get(name) {
                            if *v == true {
                                continue
                            } else {
                                return false
                            }
                        } else {
                            return false;
                        }
                    },
                    Err(e) => {
                        error!(target: "SURICATA(Flowbits::check)", error = %e)
                    }
                }
            }
            true
        },
        // 本条规则不告警
        // Tips: 请放到其它 Flowbits 规则之后！
        FlowbitCommand::NoAlert => {
            false
        },
        // 设为 true
        FlowbitCommand::Set => {
            for name in &flowbits.names {
                match FLOWBITHASH.lock() {
                    Ok(mut flowbit_hashmap) => {
                        if let Some(v) = flowbit_hashmap.get_mut(name) {
                            *v = true;
                        } else {
                            flowbit_hashmap.insert(name.to_string(), true);
                        }
                    },
                    Err(e) => {
                        error!(target: "SURICATA(Flowbits::check)", error = %e)
                    }
                }
            }
            true
        },
        // 取反
        FlowbitCommand::Toggle => {
            for name in &flowbits.names {
                match FLOWBITHASH.lock() {
                    Ok(mut flowbit_hashmap) => {
                        let v = flowbit_hashmap.entry(name.to_string()).or_insert(false);
                        v.bitxor_assign(true);
                    },
                    Err(e) => {
                        error!(target: "SURICATA(Flowbits::check)", error = %e)
                    }
                }
            }
            true
        },
        // 设为 false
        FlowbitCommand::Unset => {
            for name in &flowbits.names {
                match FLOWBITHASH.lock() {
                    Ok(mut flowbit_hashmap) => {
                        if let Some(v) = flowbit_hashmap.get_mut(name) {
                            *v = false;
                        } else {
                            flowbit_hashmap.insert(name.to_string(), false);
                        }
                    },
                    Err(e) => {
                        error!(target: "SURICATA(Flowbits::check)", error = %e)
                    }
                }
            }
            true
        }
    }
}



#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::surule::elements::{IpAddress, Port};

    use super::*;

    #[test]
    fn test_check_iplist() {
        let ipv4_addr = Ipv4Addr::from_str("192.168.1.1").unwrap();
        let list_all = IpAddressList {
            accept: None,
            except: None,
        };
        let list_except_single = IpAddressList {
            accept: None,
            except: Some(vec![IpAddress::V4Addr("192.168.1.1".parse().unwrap())]),
        };
        let list_except_range = IpAddressList {
            accept: None,
            except: Some(vec![IpAddress::V4Range("192.168.1.0/24".parse().unwrap())]),
        };

        assert!(list_all.check(&ipv4_addr));
        assert!(!list_except_single.check(&ipv4_addr));
        assert!(!list_except_range.check(&ipv4_addr));
    }

    #[test]
    fn test_check_portlist() {
        let port = 3389;
        let list_all = PortList {
            accept: None,
            except: None,
        };
        let list_except_single = PortList {
            accept: None,
            except: Some(vec![Port::Single(3389)]),
        };
        let list_except_range = PortList {
            accept: None,
            except: Some(vec![Port::new_range(3300, 3400).unwrap()]),
        };

        assert!(list_all.check(&port));
        assert!(!list_except_single.check(&port));
        assert!(!list_except_range.check(&port));
    }

    #[test]
    fn test_check_flowbits() {
        let flowbits_set = Flowbits {
            command: FlowbitCommand::Set,
            names: vec!["pop3_login".to_string()]
        };
        let flowbits_unset = Flowbits {
            command: FlowbitCommand::Unset,
            names: vec!["pop3_login".to_string()]
        };
        let flowbits_isset = Flowbits {
            command: FlowbitCommand::IsSet,
            names: vec!["pop3_login".to_string()]
        };
        let flowbits_isnotset = Flowbits {
            command: FlowbitCommand::IsNotSet,
            names: vec!["pop3_login".to_string()]
        };
        let flowbits_toggle = Flowbits {
            command: FlowbitCommand::Toggle,
            names: vec!["pop3_login".to_string()]
        };
        let flowbits_noallert = Flowbits {
            command: FlowbitCommand::NoAlert,
            names: vec![]
        };

        assert!(!flowbits_isset.check_simple());
        assert!(flowbits_isnotset.check_simple());

        assert!(flowbits_set.check_simple());
        assert!(flowbits_isset.check_simple());
        assert!(!flowbits_isnotset.check_simple());

        assert!(flowbits_unset.check_simple());
        assert!(!flowbits_isset.check_simple());
        assert!(flowbits_isnotset.check_simple());

        assert!(flowbits_toggle.check_simple());
        assert!(flowbits_isset.check_simple());
        assert!(!flowbits_isnotset.check_simple());

        assert!(!flowbits_noallert.check_simple());
    }
}
