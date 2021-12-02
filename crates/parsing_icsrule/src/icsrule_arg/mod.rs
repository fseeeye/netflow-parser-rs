mod modbus;
mod modbus_req;
mod modbus_rsp;

pub use self::modbus::ModbusArg;
pub use self::modbus_req::ModbusReqArg;
pub use self::modbus_rsp::ModbusRspArg;

use super::detect::IcsRuleDetector;
use parsing_parser::L5Packet;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "proname", content = "args")]
pub enum IcsRuleArgs {
    Modbus(Vec<ModbusArg>),
}

impl IcsRuleDetector for IcsRuleArgs {
    fn detect(&self, l5: &L5Packet) -> bool {
        match self {
            Self::Modbus(modbus_args) => {
                if modbus_args.is_empty() {
                    return true;
                }
                for modbus_arg in modbus_args {
                    if modbus_arg.detect(l5) {
                        return true;
                    }
                }
                return false;
            }
        }
    }
}
