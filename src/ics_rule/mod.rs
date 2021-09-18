mod detect;
mod rule;
mod rules;
mod rule_arg;

pub use rules::Rules;
pub use detect::detect_ics;

use std::ffi::CStr;
use libc::{c_char};

use crate::QuinPacket;
use self::detect::{CheckResult};

#[no_mangle]
pub extern "C" fn init_rules(file_ptr: *const c_char) -> *const Rules {
    let mut rules = Rules::new();

    let file = unsafe {
        assert!(!file_ptr.is_null());
        CStr::from_ptr(file_ptr)
    };
    let file_str = file.to_str().unwrap();

    if !rules.init(file_str) {
        panic!("Rules Init failed...");
    };

    println!("Rules Init done.");

    &rules
}

#[no_mangle]
pub extern "C" fn detect_ics_rules(rules_ptr: *const Rules, packet_ptr: *const QuinPacket) -> bool {
    let rules = unsafe {
        assert!(!rules_ptr.is_null());
        &*rules_ptr
    };
    let packet = unsafe {
        assert!(!packet_ptr.is_null());
        &*packet_ptr
    };

    let rst = detect_ics(rules, packet);
    match rst {
        CheckResult::Hit(_) => {
            println!("[MYPLUGIN] Hit!");
            true
        },
        CheckResult::Miss => {
            println!("[MYPLUGIN] Miss!");
            false
        }
    }
}