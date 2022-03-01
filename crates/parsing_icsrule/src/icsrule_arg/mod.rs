pub(crate) mod modbus;
pub(crate) mod s7comm;

pub use self::{
    modbus::ModbusArg,
    s7comm::S7CommArg
};

use super::detect::IcsRuleDetector;
use parsing_parser::L5Packet;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "proname", content = "args")]
pub enum IcsRuleArg {
    Modbus(ModbusArg),
    S7Comm(S7CommArg)
}

impl IcsRuleDetector for IcsRuleArg {
    fn detect(&self, l5: &L5Packet) -> bool {
        match self {
            Self::Modbus(modbus_arg) => {
                if modbus_arg.detect(l5) {
                    return true;
                }
                return false;
            },
            Self::S7Comm(_s7comm_arg) => {
                //TODO
                return false;
            }
        }
    }
}
