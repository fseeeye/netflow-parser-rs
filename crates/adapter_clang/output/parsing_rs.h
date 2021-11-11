#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


bool detect_ics_rules(const Rules *rules_ptr, const QuinPacket *packet_ptr);

const Rules *init_rules(const char *file_ptr);

const QuinPacket *parse_packet(const uint8_t *input_ptr, uint16_t input_len);

void show_packet(const QuinPacket *packet_ptr);
