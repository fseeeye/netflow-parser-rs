# 工控(白)名单规则

## 参数说明

- rid: 规则ID，请保持rid唯一性，否则会出现覆盖。
- action: pass(通过)/alert(告警)/drop(丢弃)/reject(拒绝)
- src_ip: 源地址(Optional, 没有填写null)
- src_port: 源端口(Optional)
- dire: 方向(->: 单向检测, <>: 双向检测)
- dst_ip: 目的地址(Optional)
- dst_port: 目的端口(Optional)
- msg: 提示信息(Optional)
- args: 
  -  [协议名]: 应用层协议字段规则，json格式 

## 示例
* 适配旧格式传入的rule(来自web调用，需要通过适配层调整至新格式)
```json
[
    {
        "rid": 0,
        "action": "alert",
        "proname": "Modbus",
        "src_ip": null,
        "src_port": null,
        "dir": "->",
        "dst_ip": null,
        "dst_port": 502,
        "msg": "Modbus: Read Write Multiple Register(23)",
        "args": {
            "function_code": 23,
        }
    }
]
```
* 新格式的完整rule示例(读取自本地json文件, 可选字段均可忽略不写，默认为null)
```json
[
    {
        "rid": 1,
        "proname": "Modbus",
        "action": "drop",
        "src_ip": "192.0.0.1",
        "src_port": null,
        "dir": "->",
        "dst_ip": null,
        "dst_port": null,
        "msg": "Modbus: Write Multiple Coils(15)",
        "args": [
            {
                "args_type": "ModbusReq",
                "transaction_id": null,
                "protocol_id": null,
                "length": null,
                "unit_id": null,
                "function": "15", // or "ReadWriteMultipleRegisters"
                "data": {
                    "read_start_address": null,
                    "read_count": null,
                    "write_start_address": null,
                    "write_count": null,
                    "write_byte_count": null,
                }
            },
            {
                "args_type": "ModbusRsp",
                "protocol_id": 1,
            }
        ]
    }
]
```

## Rust数据结构与json的转换说明 (for developer)
* struct: 所有struct的非标准类型(如：struct / enum等)字段附上`#[serde(flatten)]`令其平铺，以减少json不必要的嵌套。
* enum: enum结构体声明前加上`#[serde(tag="xx", content="xx")]`，将此枚举使用相邻标记的枚举表示，并为标记和内容提供给定的字段名称。同时，注释掉其相关联的choice字段（因为它已经用tag代替）。enum variant在必要时添加alias attributes`#[serde(alias = "...")`
* 去除所有非常规类型字段（如：Vec / &[u8]等），及其子结构。
* 所有字段均更改为Option<..>，以应对空值问题。