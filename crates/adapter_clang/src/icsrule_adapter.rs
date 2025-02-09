use libc::c_char;
use std::ffi::{CStr, CString};

use parsing_icsrule::HmIcsRules;
use parsing_parser::QuinPacket;
use parsing_rule::{RulesDetectorICS, DetectResultICS};

/// 初始化ICS规则结构体
#[no_mangle]
pub extern "C" fn init_ics_rules_rs() -> *mut HmIcsRules {
    let rules_ptr = Box::into_raw(Box::new(HmIcsRules::new()));

    tracing::debug!("ICS rules init Done.");

    rules_ptr
}

/// 清空ICS规则
#[no_mangle]
pub extern "C" fn free_ics_rules_rs(rules_ptr: *mut HmIcsRules) {
    if rules_ptr.is_null() {
        tracing::warn!("ICS rule free: rules ptr is null!");
        return;
    }
    unsafe { Box::from_raw(rules_ptr) };

    tracing::debug!("ICS rules free Done.");
}

/// 重新生成ICS规则
#[no_mangle]
pub extern "C" fn recreate_ics_rules_rs(rules_ptr: *mut HmIcsRules) -> *mut HmIcsRules {
    if rules_ptr.is_null() {
        tracing::warn!("ICS rule free: rules ptr is null! pass free op.");
        return Box::into_raw(Box::new(HmIcsRules::new()));
    }
    let new_rules_ptr = unsafe {
        Box::from_raw(rules_ptr);
        Box::into_raw(Box::new(HmIcsRules::new()))
    };

    tracing::debug!("ICS rules free Done.");

    new_rules_ptr
}

/// 输出ICS规则
#[no_mangle]
pub extern "C" fn show_ics_rules_rs(rules_ptr: *const HmIcsRules) -> *mut c_char {
    let mut rst = String::new();

    if rules_ptr.is_null() {
        tracing::warn!("ICS rule show: rules ptr is null!");
        return CString::new(rst).unwrap().into_raw();
    }
    let rules = unsafe { &*rules_ptr };

    for (rid, rule) in &rules.rules_inner {
        rst += format!(
            "[{}] action = {:?}, active = {}.\n",
            (*rid) as u32,
            rule.basic.action,
            rule.basic.active
        )
        .as_str();
    }
    // tracing::debug!("ICS rules show: {}", rst.trim());

    CString::new(rst).unwrap().into_raw()
}

/// 清空ICS规则输出
#[no_mangle]
pub extern "C" fn free_show_ics_rules_rs(show_rules_ptr: *mut c_char) {
    if show_rules_ptr.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(show_rules_ptr));
    }

    tracing::debug!("ICS rules show_str free Done.");
}

/// 从文件加载ICS规则
#[no_mangle]
pub extern "C" fn load_ics_rules_rs(rules_ptr: *mut HmIcsRules, file_ptr: *const c_char) -> bool {
    if rules_ptr.is_null() {
        tracing::warn!("ICS rule load: rules ptr is null!");
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

    let span = tracing::span!(tracing::Level::TRACE, "load ics rules", path = file_str);
    let _enter = span.enter();

    if rules.load_rules(file_str) {
        tracing::debug!("ICS rules load Done.");
        true
    } else {
        tracing::warn!("ICS rules load Failed!");
        false
    }
}

/// 删除ICS规则
#[no_mangle]
pub extern "C" fn delete_ics_rule_rs(rules_ptr: *mut HmIcsRules, rule_rid: usize) -> bool {
    let rules = unsafe {
        if rules_ptr.is_null() {
            tracing::warn!("ICS rule delete: rules ptr is null!");
            return false;
        }
        &mut *rules_ptr
    };

    rules.delete_rule(rule_rid);

    tracing::debug!("ICS rule delete Done.");

    return true;
}

/// 启用ICS规则
#[no_mangle]
pub extern "C" fn active_ics_rule_rs(rules_ptr: *mut HmIcsRules, rule_rid: usize) -> bool {
    let rules = unsafe {
        if rules_ptr.is_null() {
            tracing::warn!("ICS rule active: rules ptr is null!");
            return false;
        }
        &mut *rules_ptr
    };

    rules.active_rule(rule_rid);

    tracing::debug!("ICS rule active Done.");

    return true;
}

// 停用ICS规则
#[no_mangle]
pub extern "C" fn deactive_ics_rule_rs(rules_ptr: *mut HmIcsRules, rule_rid: usize) -> bool {
    let rules = unsafe {
        if rules_ptr.is_null() {
            tracing::warn!("ICS rule deactive: rules ptr is null!");
            return false;
        }
        &mut *rules_ptr
    };

    rules.deactive_rule(rule_rid);

    tracing::debug!("ICS rule deactive Done.");

    return true;
}

/// ICS规则检测
#[no_mangle]
pub extern "C" fn detect_ics_rules_rs(
    rules_ptr: *const HmIcsRules,
    packet_ptr: *const QuinPacket,
    out_rid_ptr: *mut u32,
    out_action_ptr: *mut u8,
) -> bool {
    let rules = unsafe {
        if rules_ptr.is_null() {
            tracing::warn!("ICS rule detect: rules ptr is null! return.");
            return false;
        }
        &*rules_ptr
    };
    let packet = unsafe {
        if packet_ptr.is_null() {
            tracing::warn!("ICS rule detect: packet ptr is null! return.");
            return false;
        }
        &*packet_ptr
    };
    let out_rid = unsafe {
        if out_rid_ptr.is_null() {
            tracing::warn!("ICS rule detect: out_rid ptr is null! return.");
            return false;
        }
        &mut *out_rid_ptr
    };
    let out_action = unsafe {
        if out_action_ptr.is_null() {
            tracing::warn!("ICS rule detect: out_action ptr is null! return.");
            return false;
        }
        &mut *out_action_ptr
    };

    let rst = rules.detect(packet);
    match rst {
        DetectResultICS::Hit(rid, action) => {
            tracing::trace!("ICS Rule HIT! (rid={}, action={:?})", rid, action);
            *out_rid = rid as u32;
            *out_action = super::common::rule_action_to_firewall_action(action);

            true
        }
        DetectResultICS::Miss(_) => {
            tracing::trace!("ICS Rule MISS.");
            false
        }
    }
}

/// ICS白名单规则检测
#[no_mangle]
pub extern "C" fn detect_ics_whitelist_rules_rs(
    rules_ptr: *const HmIcsRules,
    packet_ptr: *const QuinPacket,
    out_rid_ptr: *mut u32,
) -> bool {
    let rules = unsafe {
        if rules_ptr.is_null() {
            tracing::warn!("ICS rule detect: rules ptr is null! return.");
            return false;
        }
        &*rules_ptr
    };
    let packet = unsafe {
        if packet_ptr.is_null() {
            tracing::warn!("ICS rule detect: packet ptr is null! return.");
            return false;
        }
        &*packet_ptr
    };
    let out_rid = unsafe {
        if out_rid_ptr.is_null() {
            tracing::warn!("ICS rule detect: out_rid ptr is null! return.");
            return false;
        }
        &mut *out_rid_ptr
    };

    let rst = rules.detect(packet);
    match rst {
        DetectResultICS::Hit(rid, _) => {
            *out_rid = rid as u32;

            tracing::trace!("ICS Whitelist Rule HIT! (sid={})", rid);

            true
        }
        DetectResultICS::Miss(_) => {
            tracing::trace!("ICS Whitelist Rule MISS.");
            false
        }
    }
}
