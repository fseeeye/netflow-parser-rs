//! 实现 Flowbits 的 check 接口
use lazy_static::lazy_static;
use tracing::error;

use std::collections::HashMap;
use std::ops::BitXorAssign;
use std::sync::Mutex;

use crate::surule::elements::{FlowbitCommand, Flowbits};

lazy_static! {
    static ref FLOWBITHASH: Mutex<HashMap<String, bool>> = Mutex::new(HashMap::new());
}

impl Flowbits {
    #[inline]
    pub fn check(&self) -> bool {
        match self.command {
            // 检查是否为 false
            FlowbitCommand::IsNotSet => {
                for name in &self.names {
                    match FLOWBITHASH.lock() {
                        Ok(flowbit_hashmap) => {
                            if let Some(v) = flowbit_hashmap.get(name) {
                                if *v == false {
                                    continue;
                                } else {
                                    return false;
                                }
                            } else {
                                continue;
                            }
                        }
                        Err(e) => {
                            error!(target: "SURICATA(Flowbits::check)", error = %e)
                        }
                    }
                }
                true
            }
            // 检查是否为 true
            FlowbitCommand::IsSet => {
                for name in &self.names {
                    match FLOWBITHASH.lock() {
                        Ok(flowbit_hashmap) => {
                            if let Some(v) = flowbit_hashmap.get(name) {
                                if *v == true {
                                    continue;
                                } else {
                                    return false;
                                }
                            } else {
                                return false;
                            }
                        }
                        Err(e) => {
                            error!(target: "SURICATA(Flowbits::check)", error = %e)
                        }
                    }
                }
                true
            }
            // 本条规则不告警
            // Tips: 请放到其它 Flowbits 规则之后！
            FlowbitCommand::NoAlert => false,
            // 设为 true
            FlowbitCommand::Set => {
                for name in &self.names {
                    match FLOWBITHASH.lock() {
                        Ok(mut flowbit_hashmap) => {
                            if let Some(v) = flowbit_hashmap.get_mut(name) {
                                *v = true;
                            } else {
                                flowbit_hashmap.insert(name.to_string(), true);
                            }
                        }
                        Err(e) => {
                            error!(target: "SURICATA(Flowbits::check)", error = %e)
                        }
                    }
                }
                true
            }
            // 取反
            FlowbitCommand::Toggle => {
                for name in &self.names {
                    match FLOWBITHASH.lock() {
                        Ok(mut flowbit_hashmap) => {
                            let v = flowbit_hashmap.entry(name.to_string()).or_insert(false);
                            v.bitxor_assign(true);
                        }
                        Err(e) => {
                            error!(target: "SURICATA(Flowbits::check)", error = %e)
                        }
                    }
                }
                true
            }
            // 设为 false
            FlowbitCommand::Unset => {
                for name in &self.names {
                    match FLOWBITHASH.lock() {
                        Ok(mut flowbit_hashmap) => {
                            if let Some(v) = flowbit_hashmap.get_mut(name) {
                                *v = false;
                            } else {
                                flowbit_hashmap.insert(name.to_string(), false);
                            }
                        }
                        Err(e) => {
                            error!(target: "SURICATA(Flowbits::check)", error = %e)
                        }
                    }
                }
                true
            }
        }
    }
}

#[inline]
#[allow(dead_code)]
fn register_flowbits(name: String, value: bool) {
    match FLOWBITHASH.lock() {
        Ok(mut flowbit_hashmap) => {
            flowbit_hashmap.entry(name).or_insert(value);
        }
        Err(e) => {
            error!(target: "SURICATA(Flowbits::check)", error = %e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_flowbits() {
        let flowbits_set = Flowbits {
            command: FlowbitCommand::Set,
            names: vec!["pop3_login".to_string()],
        };
        let flowbits_unset = Flowbits {
            command: FlowbitCommand::Unset,
            names: vec!["pop3_login".to_string()],
        };
        let flowbits_isset = Flowbits {
            command: FlowbitCommand::IsSet,
            names: vec!["pop3_login".to_string()],
        };
        let flowbits_isnotset = Flowbits {
            command: FlowbitCommand::IsNotSet,
            names: vec!["pop3_login".to_string()],
        };
        let flowbits_toggle = Flowbits {
            command: FlowbitCommand::Toggle,
            names: vec!["pop3_login".to_string()],
        };
        let flowbits_noallert = Flowbits {
            command: FlowbitCommand::NoAlert,
            names: vec![],
        };

        assert!(!flowbits_isset.check());
        assert!(flowbits_isnotset.check());

        assert!(flowbits_set.check());
        assert!(flowbits_isset.check());
        assert!(!flowbits_isnotset.check());

        assert!(flowbits_unset.check());
        assert!(!flowbits_isset.check());
        assert!(flowbits_isnotset.check());

        assert!(flowbits_toggle.check());
        assert!(flowbits_isset.check());
        assert!(!flowbits_isnotset.check());

        assert!(!flowbits_noallert.check());
    }
}
