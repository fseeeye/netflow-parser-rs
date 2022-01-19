//! 实现 PortList 的 check 接口
use crate::surule::elements::{PortList, SurList};

impl PortList {
    #[inline]
    pub fn check(&self, compare_port: u16) -> bool {
        if self.check_accept(compare_port) {
            return !self.check_except(compare_port);
        } else {
            return false;
        }
    }

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

#[cfg(test)]
mod tests {
    use crate::surule::elements::Port;

    use super::*;

    #[test]
    fn check_portlist() {
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

        assert!(list_all.check(port));
        assert!(!list_except_single.check(port));
        assert!(!list_except_range.check(port));
    }
}
