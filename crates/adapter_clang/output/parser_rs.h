#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


/**
 * HmIcsRules是存储规则集合的数据结构，它采用 HashMap 来存取所有规则。
 * > Tips: 目前数据结构处于待完善阶段。
 */
typedef struct HmIcsRules HmIcsRules;

/**
 * QuinPacket是由 Level1 - Level5 Packet 构成的枚举结构，使用示例如下：
 * ```
 * use parsing_parser::*;
 *
 * let input = &[1,2,3,4,5,6];
 * match QuinPacket::parse_from_stream(input, &QuinPacketOptions::default()) {
 *     QuinPacket::L1(l1) => {
 *         println!("l1 packet: {:?}", l1);
 *     }
 *     QuinPacket::L2(l2) => {
 *         println!("l2 packet: {:?}", l2);
 *         println!("l2 dst mac: {:?}", l2.get_dst_mac());
 *         println!("l2 src mac: {:?}", l2.get_src_mac());
 *     }
 *     QuinPacket::L3(l3) => {
 *         println!("l3 packet: {:?}", l3);
 *         println!("l3 dst ip: {:?}", l3.get_dst_ip());
 *         println!("l3 src ip: {:?}", l3.get_src_ip());
 *     }
 *     QuinPacket::L4(l4) => {
 *         println!("l4 packet: {:?}", l4);
 *         println!("l4 dst port: {:?}", l4.get_dst_port());
 *         println!("l4 src port: {:?}", l4.get_src_port());
 *     }
 *     QuinPacket::L5(l5) => {
 *         println!("l5 packet: {:?}", l5);
 *     }
 * };
 * ```
 */
typedef struct QuinPacket QuinPacket;

/**
 * QuinPacketOptions为QuinPacket解析选项，提供多种解析特性。
 * 支持default：
 * ```
 * use parsing_parser::{QuinPacket, QuinPacketOptions};
 *
 * let input = &[1,2,3,4,5,6];
 * QuinPacket::parse_from_stream(input, &QuinPacketOptions::default());
 * ```
 */
typedef struct QuinPacketOptions QuinPacketOptions;

typedef struct VecSurules VecSurules;

/**
 * 启用ICS规则
 */
bool active_ics_rule_rs(struct HmIcsRules *rules_ptr, size_t rule_rid);

bool deactive_ics_rule_rs(struct HmIcsRules *rules_ptr, size_t rule_rid);

/**
 * 删除ICS规则
 */
bool delete_ics_rule_rs(struct HmIcsRules *rules_ptr, size_t rule_rid);

/**
 * ICS规则检测
 */
bool detect_ics_rules_rs(const struct HmIcsRules *rules_ptr,
                         const struct QuinPacket *packet_ptr,
                         uint32_t *out_rid_ptr,
                         uint8_t *out_action_ptr);

/**
 * ICS白名单规则检测
 */
bool detect_ics_whitelist_rules_rs(const struct HmIcsRules *rules_ptr,
                                   const struct QuinPacket *packet_ptr,
                                   uint32_t *out_rid_ptr);

/**
 * Suricata 规则检测
 */
bool detect_suricata_rules_rs(const struct VecSurules *rules_ptr,
                              const struct QuinPacket *packet_ptr,
                              uint32_t *out_sid_ptr,
                              uint8_t *out_action_ptr);

/**
 * 启用日志输出
 */
void enable_tracing_rs(void);

/**
 * 清空ICS规则
 */
void free_ics_rules_rs(struct HmIcsRules *rules_ptr);

/**
 * 释放数据包解析结果内存
 */
void free_packet_rs(struct QuinPacket *packet_ptr);

/**
 * 清空ICS规则输出
 */
void free_show_ics_rules_rs(char *show_rules_ptr);

/**
 * 获得解析结果(json)
 */
char *get_parsing_json_rs(const struct QuinPacket *packet_ptr,
                          bool is_match,
                          uint8_t alert_target,
                          uint8_t alert_type,
                          uint8_t direction,
                          size_t packet_len);

/**
 * 获得与防火墙匹配的协议id
 */
uint8_t get_protocol_id_rs(const struct QuinPacket *packet_ptr);

/**
 * 初始化ICS规则结构体
 */
struct HmIcsRules *init_ics_rules_rs(void);

/**
 * 初始化数据包解析选项
 */
struct QuinPacketOptions *init_parse_option_rs(void);

/**
 * 初始化 Suricata 规则结构体
 */
struct VecSurules *init_suricata_rules_rs(void);

/**
 * 判断是否为工控协议
 */
bool is_ics_rs(const struct QuinPacket *packet_ptr);

/**
 * 从文件加载ICS规则
 */
bool load_ics_rules_rs(struct HmIcsRules *rules_ptr, const char *file_ptr);

/**
 * 从文件加载 Suricata 规则
 */
bool load_suricata_rules_rs(struct VecSurules *rules_ptr, const char *file_ptr);

/**
 * 解析数据包
 */
struct QuinPacket *parse_packet_rs(const uint8_t *input_ptr,
                                   uint16_t input_len,
                                   const struct QuinPacketOptions *option_ptr);

/**
 * 重新生成ICS规则
 */
struct HmIcsRules *recreate_ics_rules_rs(struct HmIcsRules *rules_ptr);

/**
 * 输出ICS规则
 */
char *show_ics_rules_rs(const struct HmIcsRules *rules_ptr);

/**
 * 展示数据包解析结果
 */
void show_packet_rs(const struct QuinPacket *packet_ptr);

/**
 * 输出 Suricata 规则
 */
char *show_suricata_rules_rs(const struct VecSurules *rules_ptr);
