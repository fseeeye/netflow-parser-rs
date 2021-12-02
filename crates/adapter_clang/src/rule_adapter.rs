use libc::c_char;
use std::ffi::CStr;

use parsing_icsrule::HmIcsRules;
use parsing_parser::QuinPacket;
use parsing_rule::{DetectResult, Rules};

#[no_mangle]
pub extern "C" fn init_rules(file_ptr: *const c_char) -> *const HmIcsRules {
    let mut rules = HmIcsRules::new();

    let file = unsafe {
        assert!(!file_ptr.is_null());
        CStr::from_ptr(file_ptr)
    };
    let file_str = file.to_str().unwrap();

    if !rules.init(file_str) {
        panic!("[PARSING-RS] Rules Init failed...");
    };

    println!("[PARSING-RS] Rules Init done.");

    &rules
}

#[no_mangle]
pub extern "C" fn detect_ics_rules(
    rules_ptr: *const HmIcsRules,
    packet_ptr: *const QuinPacket,
) -> bool {
    let rules = unsafe {
        assert!(!rules_ptr.is_null());
        &*rules_ptr
    };
    let packet = unsafe {
        assert!(!packet_ptr.is_null());
        &*packet_ptr
    };

    let rst = rules.detect(packet);
    match rst {
        DetectResult::Hit(_) => {
            // println!("Hit!");
            true
        }
        DetectResult::Miss => {
            // println!("Miss!");
            false
        }
    }
}
