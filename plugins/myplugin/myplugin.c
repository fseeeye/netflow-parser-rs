/*
 * myplugin.c - skeleton vpp engine plug-in
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
 * 可以理解为main.c
 * 结点初始化VNET_FEATURE_INIT，注册消息队列到全局；注册CLI命令及其响应函数，同时启动定时扫描进程,见xxx_periodic.c文件；
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <myplugin/myplugin.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

#include <myplugin/myplugin.api_enum.h>
#include <myplugin/myplugin.api_types.h>

#define REPLY_MSG_ID_BASE mmp->msg_id_base
#include <vlibapi/api_helper_macros.h>

#include "parser_rs.h"

myplugin_main_t myplugin_main;

/* Action function shared between message handler and debug CLI */

// 真正响应CLI命令的函数
int myplugin_enable_disable (myplugin_main_t * mmp, u32 sw_if_index,
                                   int enable_disable)
{
	vnet_sw_interface_t * sw;
	int rv = 0;

	/* Utterly wrong? */
	if (pool_is_free_index (mmp->vnet_main->interface_main.sw_interfaces,
							sw_if_index))
		return VNET_API_ERROR_INVALID_SW_IF_INDEX;

	/* Not a physical port? */
	sw = vnet_get_sw_interface (mmp->vnet_main, sw_if_index);
	if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
		return VNET_API_ERROR_INVALID_SW_IF_INDEX;

	// 创建监控进程，此函数在`myplugin_periodic.c`中实现
	myplugin_create_periodic_process (mmp);

	printf("myplugin enalbe-disable: %d\n", enable_disable);

	// 执行结点功能函数
	vnet_feature_enable_disable ("device-input", "myplugin",
								sw_if_index, enable_disable, 0, 0);

	/* Send an event to enable/disable the periodic scanner process */
	// 给监控程序发送开关插件事件，也就是让插件enable/disable
	vlib_process_signal_event (mmp->vlib_main,
								mmp->periodic_node_index,
								MYPLUGIN_EVENT_PERIODIC_ENABLE_DISABLE,
								(uword)enable_disable);
	return rv;
}

// 命令行解析函数，并在其中调用myplugin_enable_disable函数
static clib_error_t *
myplugin_enable_disable_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
	myplugin_main_t * mmp = &myplugin_main;
	u32 sw_if_index = ~0;
	int enable_disable = 1;

	int rv;

	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
	{
		if (unformat (input, "disable"))
			enable_disable = 0;
		else if (unformat (input, "%U", unformat_vnet_sw_interface,
							mmp->vnet_main, &sw_if_index))
			;
		else
			break;
	}

	if (sw_if_index == ~0)
		return clib_error_return (0, "Please specify an interface...");

	rv = myplugin_enable_disable (mmp, sw_if_index, enable_disable);

	switch(rv)
	{
		case 0:
			break;

		case VNET_API_ERROR_INVALID_SW_IF_INDEX:
			return clib_error_return
			(0, "Invalid interface, only works on physical ports");
			break;

		case VNET_API_ERROR_UNIMPLEMENTED:
			return clib_error_return (0, "Device driver doesn't support redirection");
			break;

		default:
			return clib_error_return (0, "myplugin_enable_disable returned %d",
									rv);
	}

	return 0;
}

/* *INDENT-OFF* */
// "注册CLI命令"
// 通过命令行来触发VLIB_CLI_COMMAND (myplugin_enable_disable_command, static)事件
// CLI命令是myplugin enable-disable eth0，*挂载成功后该插件才会work*。关闭某端口的该功能myplugin enable-disable eth0 disable。
VLIB_CLI_COMMAND (myplugin_enable_disable_command, static) =
{
	.path = "myplugin enable-disable",
	.short_help =
	"myplugin enable-disable <interface-name> [disable]",
	.function = myplugin_enable_disable_command_fn, // .funtion指向了回调函数
};
/* *INDENT-ON* */

/* API message handler */
// "API消息处理函数"，应该是结合测试程序VAT使用的。
// 该函数主要作为VPP服务端用于开启关闭插件功能，VAT客户端实现见myplugin_test.c文件，同时它们之间交互接口的定义见C语言的myplugin.api。
static void vl_api_myplugin_enable_disable_t_handler
(vl_api_myplugin_enable_disable_t * mp)
{
	vl_api_myplugin_enable_disable_reply_t * rmp;
	myplugin_main_t * mmp = &myplugin_main;
	int rv;

	rv = myplugin_enable_disable (mmp, ntohl(mp->sw_if_index),
										(int) (mp->enable_disable));

	REPLY_MACRO(VL_API_MYPLUGIN_ENABLE_DISABLE_REPLY);
}

/* API definitions */
#include <myplugin/myplugin.api.c>

// "节点初始化1"：初始化插件
// 将插件挂接到 VPP 二进制 API 消息调度程序中，并将其消息添加到 VPP 的全局 “message-name_crc” 哈希表中
static clib_error_t * myplugin_init (vlib_main_t * vm)
{
	myplugin_main_t * mmp = &myplugin_main; // 实例化myplugin_main_t结构体，赋值各个参数
	clib_error_t * error = 0;

	mmp->vlib_main = vm;
	mmp->vnet_main = vnet_get_main();

	/* Add our API messages to the global name_crc hash table */
	mmp->msg_id_base = setup_message_id_table (); // 将本API消息注册到全局Hash表中

	/* 解析选项初始化 */
	mmp->parser_options = init_parse_option();
	/* 匹配规则初始化 */
	mmp->ics_rules = init_rules("/home/bolean/parsing-rs/examples/ics_rules.json");

	return error;
}

VLIB_INIT_FUNCTION (myplugin_init); // 这里定义VLIB初始化函数并绑定到VLIB库上

/* *INDENT-OFF* */
// "节点初始化2": 关联插件对应节点(节点包含节点运行函数，即feature)，并定义feature运行顺序
// 绑定vnet的feature和vlib的节点名称，并定义已经初始化的节点(VLIB_REGISTER_NODE)的feature(VLIB_NODE_FN)在什么节点的feature前运行
// 即，设置vpp消息API表 —— “请在某某接口上启用我的feature”
// The boilerplate generator places the graph node dispatch function onto the “device-input” feature arc. This may or may not be useful.
// VLIB与VNET是层级调用关系
// 第一个参数`myplugin`结构体的定义在vnet/feature/feature.h中
VNET_FEATURE_INIT (myplugin, static) =
{
	// .arc_name = "ip4-unicast",
	// .node_name = "myplugin",
	// .runs_before = VNET_FEATURES ("ip4-lookup"),
	.arc_name = "device-input", // feature的父arc名称，可以通过show feature查看
	.node_name = "myplugin", // 设置节点名称，将VLIB中定义的myplugin功能函数(VLIB_NODE_FN)通过.node_name来与.arc_name联系起来
	.runs_before = VNET_FEATURES ("ethernet-input"), // 让其在 ethernet-input 结点运行之前运行
	// .runs_after = VNET_FEATURES ("xxx"),
};
/* *INDENT-ON */

/* *INDENT-OFF* */
// 注册插件，把插件名称/描述等注册到vpp
// Vpp itself uses dlsym(…) to track down the vlib_plugin_registration_t generated by the VLIB_PLUGIN_REGISTER macro:
VLIB_PLUGIN_REGISTER () =
{
	.version = VPP_BUILD_VER,
	.description = "My Plugin Enabled by Default...",
	.default_disabled = 0, // added: default enable(0) / disable(1)
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
