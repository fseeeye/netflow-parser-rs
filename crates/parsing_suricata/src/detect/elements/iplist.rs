//! 实现 IpAddressList 的 check 接口
use std::net::Ipv4Addr;

use crate::surule::elements::{IpAddressList, SurList};

use super::SuruleElementDetector;


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


#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::surule::elements::IpAddress;
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
}