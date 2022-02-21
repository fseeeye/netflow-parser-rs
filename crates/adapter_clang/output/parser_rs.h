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
bool detect_ics_rules_rs(const struct HmIcsRules *rules_ptr, const struct QuinPacket *packet_ptr);

/**
 * 启用日志输出
 */
void enable_tracing_rs(void);

/**
 * 清空ICS规则 (recreate)
 */
void free_ics_rules_rs(struct HmIcsRules *rules_ptr);

/**
 * 清空ICS规则输出
 */
void free_show_ics_rules_rs(char *show_rules_ptr);

/**
 * 初始化ICS规则结构体
 */
struct HmIcsRules *init_ics_rules_rs(void);

const struct QuinPacketOptions *init_parse_option_rs(void);

/**
 * 从文件加载ICS规则
 */
bool load_ics_rules_rs(struct HmIcsRules *rules_ptr, const char *file_ptr);

const struct QuinPacket *parse_packet_rs(const uint8_t *input_ptr,
                                         uint16_t input_len,
                                         const struct QuinPacketOptions *option_ptr);

/**
 * 输出ICS规则
 */
char *show_ics_rules_rs(const struct HmIcsRules *rules_ptr);

void show_packet_rs(const struct QuinPacket *packet_ptr);
