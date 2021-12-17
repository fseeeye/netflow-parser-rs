use super::{modbus_rsp::ModbusRspArg, ModbusReqArg};
use crate::detect::IcsRuleDetector;
use parsing_parser::{ApplicationLayer, L5Packet};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "args_type")]
pub enum ModbusArg {
    ModbusReq(ModbusReqArg), // Q: Modbus? or split
    ModbusRsp(ModbusRspArg),
}

impl IcsRuleDetector for ModbusArg {
    fn detect(&self, l5: &L5Packet) -> bool {
        match self {
            Self::ModbusReq(modbus_req_arg) => {
                // 判断规则类型和packet的应用层协议类型是否匹配
                match &l5.application_layer {
                    ApplicationLayer::ModbusReq(modbus_req) => {
                        return modbus_req_arg.check_arg(modbus_req)
                    }
                    _ => return false,
                }
            }
            Self::ModbusRsp(modbus_rsp_arg) => match &l5.application_layer {
                ApplicationLayer::ModbusRsp(modbus_rsp) => {
                    return modbus_rsp_arg.check_arg(modbus_rsp)
                }
                _ => return false,
            },
        }
    }
}
