mod modbus;
mod modbus_req;
mod modbus_rsp;

pub use self::modbus::ModbusArg;
pub use self::modbus_req::ModbusReqArg;
pub use self::modbus_rsp::ModbusRspArg;

use serde::{Deserialize, Serialize};
use parsing_parser::L5Packet;
use super::detect::RuleDetector;


#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "proname", content = "args")]
pub enum RuleArgs {
    Modbus(Vec<ModbusArg>)
}

impl RuleDetector for RuleArgs {
    fn detect(&self, l5: &L5Packet) -> bool {
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