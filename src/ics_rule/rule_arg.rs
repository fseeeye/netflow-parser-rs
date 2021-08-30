mod modbus_arg;
mod modbus_req_arg;
mod modbus_rsp_arg;

use crate::RuleDetector;

pub use self::modbus_arg::ModbusArg;
pub use self::modbus_req_arg::ModbusReqArg;
pub use self::modbus_rsp_arg::ModbusRspArg;


use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "proname", content = "args")]
pub enum RuleArgs {
    Modbus(Vec<ModbusArg>)
}

impl RuleDetector for RuleArgs {
    fn detect(&self, l5: &crate::L5Packet) -> bool {
        match self {
            Self::Modbus(modbus_args) => {
                if modbus_args.is_empty() {
                    return true
                }
                for modbus_arg in modbus_args {
                    if modbus_arg.detect(l5) {
                        return true
                    }
                }
                return false
            },
        }
    }
}