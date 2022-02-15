pub(crate) mod modbus;

pub use self::modbus::ModbusArg;

use super::detect::IcsRuleDetector;
use parsing_parser::L5Packet;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "proname", content = "args")]
pub enum IcsRuleArg {
    Modbus(ModbusArg),
}

impl IcsRuleDetector for IcsRuleArg {
    fn detect(&self, l5: &L5Packet) -> bool {
        match self {
            Self::Modbus(modbus_arg) => {
                if modbus_arg.detect(l5) {
                    return true;
                }
                return false;
            }
        }
    }
}
