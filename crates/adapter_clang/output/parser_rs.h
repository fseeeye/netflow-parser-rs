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
 * use parsing_rs::*;
 *
 * match parse_quin_packet(input, QuinPacketOptions::default()) {
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
 * parse_quin_packet(input, QuinPacketOptions::default())
 * ```
 */
typedef struct QuinPacketOptions QuinPacketOptions;

bool detect_ics_rules(const struct HmIcsRules *rules_ptr, const struct QuinPacket *packet_ptr);

const struct QuinPacketOptions *init_parse_option(void);

const struct HmIcsRules *init_rules(const char *file_ptr);

const struct QuinPacket *parse_packet(const uint8_t *input_ptr,
                                      uint16_t input_len,
                                      const struct QuinPacketOptions *option_ptr);

void show_packet(const struct QuinPacket *packet_ptr);
