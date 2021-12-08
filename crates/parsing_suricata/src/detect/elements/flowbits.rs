//! 实现 Flowbits 的 check 接口
use lazy_static::lazy_static;
use tracing::error;

use std::sync::Mutex;
use std::collections::HashMap;
use std::ops::BitXorAssign;

use crate::surule::elements::{Flowbits, FlowbitCommand};
use super::{SuruleElementDetector, SuruleElementSimpleDetector};


lazy_static! {
    static ref FLOWBITHASH: Mutex<HashMap<String, bool>> = Mutex::new(HashMap::new());
}

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

#[allow(dead_code)]
fn register_flowbits(name: String, value: bool) {
    match FLOWBITHASH.lock() {
        Ok(mut flowbit_hashmap) => {
            flowbit_hashmap.entry(name).or_insert(value);
        },
        Err(e) => {
            error!(target: "SURICATA(Flowbits::check)", error = %e);
        }
    }
}

fn check_flowbits(flowbits: &Flowbits) -> bool {
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
    use super::*;

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