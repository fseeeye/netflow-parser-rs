// use serde::{Serialize, Deserialize};

// use crate::{L5Packet, RuleTrait, ics_rule::rule_arg::ModbusArg, layer::ApplicationLayer};
// use super::basic_rule::BasicRule;

// #[derive(Serialize, Deserialize, Debug)]
// pub struct ModbusRule {
//     #[serde(flatten)]
//     pub basic: BasicRule,
//     pub args: Option<Vec<ModbusArg>>,
// }

// impl RuleTrait for ModbusRule {
//     fn check_rule(&self, l5: &L5Packet) -> bool {
//         // 若发生basic字段匹配不相符，则返回false
//         if !self.basic.check_rule(&l5) {
//             return false;
//         }

//         // 判断args参数是否设置
//         if let Some(args) = &self.args {
//             match &l5.application_layer {
//                 ApplicationLayer::ModbusReq(modbus_req) => {
//                     // 任意一个arg匹配正确即返回true
//                     for arg in args {
//                         // 取出与协议类型匹配的arg
//                         if let ModbusArg::ModbusReq(modbus_req_arg) = arg {
//                             if modbus_req_arg.check_arg(modbus_req) {
//                                 return true;
//                             }
//                         }
//                     }
//                     return false
//                 },
//                 ApplicationLayer::ModbusRsp(modbus_rsp) => {
//                     // 任意一个arg匹配正确即返回true
//                     for arg in args {
//                         // 取出与协议类型匹配的arg
//                         if let ModbusArg::ModbusRsp(modbus_rsp_arg) = arg {
//                             if modbus_rsp_arg.check_arg(modbus_rsp) {
//                                 return true;
//                             }
//                         }
//                     }
//                     return false
//                 },
//                 _ => {
//                     // 如果packet的应用层不是Modbus协议，则返回false。
//                     return false
//                 }
//             }
//         }

//         // basic字段匹配正确，且args为空，则返回true
//         true
//     }
// }