use libc::c_char;
use std::ffi::CStr;

use parsing_icsrule::HmIcsRules;
use parsing_parser::QuinPacket;
use parsing_rule::{DetectResult, RulesDetector};

/// 初始化ICS规则结构体
#[no_mangle]
pub extern "C" fn init_ics_rules() -> *mut HmIcsRules {
    let mut rules = HmIcsRules::new();

    tracing::debug!("ICS rules int Done.");
    println!("[PARSING-RS] Rules int done.");

    &mut rules
}

/// 从文件加载ICS规则
#[no_mangle]
pub extern "C" fn load_ics_rules(rules_ptr: *mut HmIcsRules, file_ptr: *const c_char) -> bool {
    let rules = unsafe {
        if rules_ptr.is_null() {
            return false;
        }
        &mut *rules_ptr
    };

    let file = unsafe {
        if file_ptr.is_null() {
            return false;
        }
        CStr::from_ptr(file_ptr)
    };
    let file_str = file.to_str().unwrap();

    let span = tracing::span!(tracing::Level::TRACE, "load ics rules", path=file_str);
    let _enter = span.enter();

    if rules.load_rules(file_str) {
        tracing::debug!("ICS rules load Done.");
        println!("[PARSING-RS] Rules Init done.");
        true
    } else {
        tracing::debug!("ICS rules load Failed!");
        println!("[PARSING-RS] Rules Init failed!");
        false
    }
}

/// 删除ICS规则
#[no_mangle]
pub extern "C" fn delete_ics_rule(rules_ptr: *mut HmIcsRules, rule_rid: usize) -> bool {
    let rules = unsafe {
        if rules_ptr.is_null() {
            return false;
        }
        &mut *rules_ptr
    };

    rules.delete_rule(rule_rid);
    
    tracing::debug!("ICS rule delete Done.");
    println!("[PARSING-RS] Rule delete done.");

    return true;
}

/// 启用ICS规则
#[no_mangle]
pub extern "C" fn active_ics_rule(rules_ptr: *mut HmIcsRules, rule_rid: usize) -> bool {
    let rules = unsafe {
        if rules_ptr.is_null() {
            return false;
        }
        &mut *rules_ptr
    };

    rules.active_rule(rule_rid);

    tracing::debug!("ICS rule active Done.");
    println!("[PARSING-RS] Rule active done.");

    return true;
}

// 停用ICS规则
#[no_mangle]
pub extern "C" fn deactive_ics_rule(rules_ptr: *mut HmIcsRules, rule_rid: usize) -> bool {
    let rules = unsafe {
        if rules_ptr.is_null() {
            return false;
        }
        &mut *rules_ptr
    };

    rules.deactive_rule(rule_rid);

    tracing::debug!("ICS rule deactive Done.");
    println!("[PARSING-RS] Rule deactive done.");

    return true;
}

/// ICS规则检测
#[no_mangle]
pub extern "C" fn detect_ics_rules(
    rules_ptr: *const HmIcsRules,
    packet_ptr: *const QuinPacket,
) -> bool {
    let rules = unsafe {
        if rules_ptr.is_null() {
            return false;
        }
        &*rules_ptr
    };
    let packet = unsafe {
        if packet_ptr.is_null() {
            return false;
        }
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
