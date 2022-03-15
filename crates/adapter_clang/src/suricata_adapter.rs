use libc::c_char;
use std::ffi::{CStr, CString};

use parsing_parser::QuinPacket;
use parsing_rule::{DetectResult, RulesDetector};
use parsing_suricata::{Surules, VecSurules};

/// 初始化 Suricata 规则结构体
#[no_mangle]
pub extern "C" fn init_suricata_rules_rs() -> *mut VecSurules {
    let rules_ptr = Box::into_raw(Box::new(VecSurules::default()));

    tracing::debug!("Suricata rules init Done.");

    rules_ptr
}

/// 从文件加载 Suricata 规则
#[no_mangle]
pub extern "C" fn load_suricata_rules_rs(
    rules_ptr: *mut VecSurules,
    file_ptr: *const c_char,
) -> bool {
    if rules_ptr.is_null() {
        tracing::warn!("Suricata rule load: rules ptr is null!");
        return false;
    }
    let rules = unsafe { &mut *rules_ptr };

    let file = unsafe {
        if file_ptr.is_null() {
            return false;
        }
        CStr::from_ptr(file_ptr)
    };
    let file_str = file.to_str().unwrap();

    let span = tracing::span!(
        tracing::Level::TRACE,
        "load suricata rules",
        path = file_str
    );
    let _enter = span.enter();

    match rules.load_from_file(file_str) {
        Ok(_) => {
            tracing::debug!("Suricata rules load Done.");
            true
        }
        Err(_) => {
            tracing::warn!("Suricata rules load Failed!");
            false
        }
    }
}

/// 输出 Suricata 规则
#[no_mangle]
pub extern "C" fn show_suricata_rules_rs(rules_ptr: *const VecSurules) -> *mut c_char {
    let mut rst = String::new();

    if rules_ptr.is_null() {
        tracing::warn!("Suricata rule show: rules ptr is null!");
        return CString::new(rst).unwrap().into_raw();
    }
    let rules = unsafe { &*rules_ptr };

    rst += format!("TCP Rules:\n").as_str();
    let mut i: u8 = 0;
    for tcp_rule in &rules.tcp_rules {
        rst += format!("[{}] action = {:?}.\n", i, tcp_rule.action).as_str();
        i += 1;
    }
    rst += format!("UDP Rules:\n").as_str();
    i = 0;
    for udp_rule in &rules.udp_rules {
        rst += format!("[{}] action = {:?}.\n", i, udp_rule.action).as_str();
        i += 1;
    }
    // tracing::debug!("Suricata rules show: {}", rst.trim());

    CString::new(rst).unwrap().into_raw()
}

/// Suricata 规则检测
#[no_mangle]
pub extern "C" fn detect_suricata_rules_rs(
    rules_ptr: *const VecSurules,
    packet_ptr: *const QuinPacket,
    out_sid_ptr: *mut u32,
    out_action_ptr: *mut u8,
) -> bool {
    let rules = unsafe {
        if rules_ptr.is_null() {
            tracing::warn!("Suricata rule detect: rules ptr is null! return.");
            return false;
        }
        &*rules_ptr
    };
    let packet = unsafe {
        if packet_ptr.is_null() {
            tracing::warn!("Suricata rule detect: packet ptr is null! return.");
            return false;
        }
        &*packet_ptr
    };
    let out_sid = unsafe {
        if out_sid_ptr.is_null() {
            tracing::warn!("Suricata rule detect: out_sid ptr is null! return.");
            return false;
        }
        &mut *out_sid_ptr
    };
    let out_action = unsafe {
        if out_action_ptr.is_null() {
            tracing::warn!("Suricata rule detect: out_action ptr is null! return.");
            return false;
        }
        &mut *out_action_ptr
    };

    let rst = rules.detect(packet);
    match rst {
        DetectResult::Hit(rid, action) => {
            tracing::debug!("Suricata Rule HIT! (sid={}, action={:?})", rid, action);

            *out_sid = rid as u32;
            *out_action = super::common::rule_action_to_firewall_action(action);

            true
        }
        DetectResult::Miss => {
            tracing::trace!("Suricata Rule MISS.");
            false
        }
    }
}
