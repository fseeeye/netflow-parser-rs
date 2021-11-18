/*
 * node.c - skeleton vpp engine plug-in dual-loop node skeleton
 *
 * Copyright (c) <current-year> <your-organization>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 用于生成图节点调度函数，也就是插件主要的处理逻辑。为避免重复造轮子，其实只要改_x1/_x2/_x4这些包处理代码即可
 * 完成结点注册VLIB_REGISTER_NODE以及插件功能实现函数VLIB_NODE_FN
 */
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <myplugin/myplugin.h>

#include "parser_rs.h"

extern myplugin_main_t myplugin_main;

typedef struct 
{
  u32 next_index;
  u32 sw_if_index;
//   u8 new_src_mac[6];
//   u8 new_dst_mac[6];
} myplugin_trace_t;

#ifndef CLIB_MARCH_VARIANT
// static u8 *
// my_format_mac_address (u8 * s, va_list * args)
// {
//   u8 *a = va_arg (*args, u8 *);
//   return format (s, "%02x:%02x:%02x:%02x:%02x:%02x",
// 		 a[0], a[1], a[2], a[3], a[4], a[5]);
// }

/* packet trace format function */
static u8 * format_myplugin_trace (u8 * s, va_list * args)
{
	CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
	CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
	myplugin_trace_t * t = va_arg (*args, myplugin_trace_t *);
	
	s = format (s, "MYPLUGIN: sw_if_index %d, next index %d\n",
				t->sw_if_index, t->next_index);
	// s = format (s, "  new src %U -> new dst %U",
	//             my_format_mac_address, t->new_src_mac, 
	//             my_format_mac_address, t->new_dst_mac);
	return s;
}

vlib_node_registration_t myplugin_node;

#endif /* CLIB_MARCH_VARIANT */

#define foreach_myplugin_error \
_(SWAPPED, "Mac swap packets processed")

typedef enum {
#define _(sym,str) MYPLUGIN_ERROR_##sym,
  	foreach_myplugin_error
#undef _
  	MYPLUGIN_N_ERROR,
} myplugin_error_t;

#ifndef CLIB_MARCH_VARIANT
static char * myplugin_error_strings[] = 
{
#define _(sym,string) string,
  	foreach_myplugin_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

typedef enum 
{
  	MYPLUGIN_NEXT_INTERFACE_OUTPUT,
  	MYPLUGIN_N_NEXT,
} myplugin_next_t;

#define foreach_mac_address_offset              \
_(0)                                            \
_(1)                                            \
_(2)                                            \
_(3)                                            \
_(4)                                            \
_(5)


// "结点功能实现函数"
// 主要实现功能：对input结点收进来的报文，做一个src/dst mac交换，然后源端口发送出去。因其参数为myplugin_node，所以与注册结点函数放在同一文件中。
// 该结点功能函数被调用发生在：myplugin.c文件的 vnet_feature_enable_disable 函数中。VNET_FEATURE_INIT中关联了VLIB和VNET
VLIB_NODE_FN (myplugin_node) (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
	myplugin_main_t * mmp = &myplugin_main;
	u32 n_left_from, * from, * to_next;
	myplugin_next_t next_index;
	u32 pkts_swapped = 0;

	from = vlib_frame_vector_args (frame);
	n_left_from = frame->n_vectors;
	next_index = node->cached_next_index;

  	while (n_left_from > 0)
    {
      	u32 n_left_to_next;

      	vlib_get_next_frame (vm, node, next_index,
				to_next, n_left_to_next);

      	while (n_left_from > 0 && n_left_to_next > 0)
	    {
			u32 bi0;
			vlib_buffer_t * b0;
			u32 next0 = MYPLUGIN_NEXT_INTERFACE_OUTPUT;
			u32 sw_if_index0;

			/* speculatively enqueue b0 to the current next frame */
			bi0 = from[0];
			to_next[0] = bi0;
			from += 1;
			to_next += 1;
			n_left_from -= 1;
			n_left_to_next -= 1;

			b0 = vlib_get_buffer (vm, bi0);

			vnet_feature_next(&next0, b0);

			/* 
			* Direct from the driver, we should be at offset 0
			* aka at &b0->data[0]
			*/
			ASSERT (b0->current_data == 0);

			sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
			
			
			/* 用户自定义内容 Start */
			// printf("[MYPLUGIN] GET NEW PACKET!\n");
			// printf("length: %u\n", packet_length);
			// printf("bytes: ");
			// for (int i = 0; i < packet_length; i++)
			// {
			// 	printf("%02x", inputs[i]);
			// }
			// printf("\n");
			// ethernet_header_t *en0;
			// en0 = vlib_buffer_get_current (b0);
			// 获取数据包字节流
			// uint8_t* inputs = vlib_buffer_get_current (b0);
			// 解析数据包
			// const struct QuinPacket * quinpakcet = parse_packet(inputs, b0->current_length, mmp->parser_options);
			// 打印解析结果
			// show_packet(quinpakcet);
			// 匹配规则
			// bool detect_rst = detect_ics_rules(mmp->ics_rules, quinpakcet);
			/* 用户自定义内容 End */

			/* Send pkt back out the RX interface */
			// vnet_buffer(b0)->sw_if_index[VLIB_TX] = sw_if_index0;

			if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
							&& (b0->flags & VLIB_BUFFER_IS_TRACED))) {
				myplugin_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
				t->sw_if_index = sw_if_index0;
				t->next_index = next0;
			}
			
			pkts_swapped += 1;

          	/* verify speculative enqueue, maybe switch current next frame */
	        vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
				to_next, n_left_to_next,
				bi0, next0);
		}

      	vlib_put_next_frame (vm, node, next_index, n_left_to_next);
	}

  	vlib_node_increment_counter (vm, myplugin_node.index, 
                               MYPLUGIN_ERROR_SWAPPED, pkts_swapped);
  	return frame->n_vectors;
}

/* *INDENT-OFF* */
// "注册节点"
// 生成一堆该Node的构造/析构函数
#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (myplugin_node) = 
{
	.name = "myplugin", // 插件节点名称
	.vector_size = sizeof (u32), // size of scalar and vector arguments in bytes
	.format_trace = format_myplugin_trace, // 调试利器，调用trace函数，在show trace命令中输出
	.type = VLIB_NODE_TYPE_INTERNAL, // 内部节点类型，VLIB_NODE_TYPE_INTERNAL为数据包处理业务的node类型
	
	.n_errors = ARRAY_LEN(myplugin_error_strings),
	.error_strings = myplugin_error_strings,

	.n_next_nodes = MYPLUGIN_N_NEXT,

	/* edit / add dispositions here */
	// 数据包下一个处理节点(feature)的集合
	.next_nodes = {
			[MYPLUGIN_NEXT_INTERFACE_OUTPUT] = "interface-output",
			// [MYPLUGIN_DROP]					 = "error-drop",
	},
};
#endif /* CLIB_MARCH_VARIANT */
/* *INDENT-ON* */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
