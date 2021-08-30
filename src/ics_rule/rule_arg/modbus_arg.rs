use serde::{Serialize, Deserialize};

use crate::{RuleDetector, layer::ApplicationLayer};

use super::{ModbusReqArg, modbus_rsp_arg::ModbusRspArg};

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "args_type")]
pub enum ModbusArg {
    ModbusReq(ModbusReqArg), // Q: Modbus? or split
    ModbusRsp(ModbusRspArg),
}

impl RuleDetector for ModbusArg {
    fn detect(&self, l5: &crate::L5Packet) -> bool {
        match self {
            Self::ModbusReq(modbus_req_arg) => {
                // 判断规则类型和packet的应用层协议类型是否匹配
                match &l5.application_layer {
                    ApplicationLayer::ModbusReq(modbus_req) => {
                        return modbus_req_arg.check_arg(modbus_req)
                    },
                    _ => {
                        return false
                    }
                }
            },
            Self::ModbusRsp(modbus_rsp_arg) => {
                match &l5.application_layer {
                    ApplicationLayer::ModbusRsp(modbus_rsp) => {
                        return modbus_rsp_arg.check_arg(modbus_rsp)
                    },
                    _ => {
                        return false
                    }
                }
            }
        }
    }
}