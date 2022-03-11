pub(crate) mod modbus;
pub(crate) mod s7comm;
pub(crate) mod dnp3;
pub(crate) mod fins;
pub(crate) mod opcua;

use self::{fins::FinsArg, opcua::OpcuaArg};
pub use self::{
    modbus::ModbusArg,
    s7comm::S7CommArg,
    dnp3::Dnp3Arg
};

use super::detect::IcsRuleDetector;
use parsing_parser::L5Packet;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "proname", content = "args")]
pub enum IcsRuleArg {
    Modbus(ModbusArg),
    S7COMM(S7CommArg),
    DNP3(Dnp3Arg),
    FINS(FinsArg),
    OPCUA(OpcuaArg)
}

impl IcsRuleDetector for IcsRuleArg {
    fn detect(&self, l5: &L5Packet) -> bool {
        match self {
            Self::Modbus(modbus_arg) => {
                modbus_arg.detect(l5)
            },
            Self::S7COMM(s7comm_arg) => {
                s7comm_arg.detect(l5)
            },
            Self::DNP3(dnp3_arg) => {
                dnp3_arg.detect(l5)
            }
            Self::FINS(fins_arg) => {
                fins_arg.detect(l5)
            }
            Self::OPCUA(opcua_arg) => {
                opcua_arg.detect(l5)
            }
        }
    }
}
