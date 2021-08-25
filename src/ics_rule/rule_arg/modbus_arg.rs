use serde::{Serialize, Deserialize};

use super::{ModbusReqArg, modbus_rsp_arg::ModbusRspArg};

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "args_type")]
pub enum ModbusArg {
    ModbusReq(ModbusReqArg), // Q: Modbus? or split
    ModbusRsp(ModbusRspArg),
}