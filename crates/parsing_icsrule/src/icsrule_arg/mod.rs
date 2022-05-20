pub(crate) mod dnp3;
pub(crate) mod fins;
pub(crate) mod modbus;
pub(crate) mod opcua;
pub(crate) mod s7comm;
pub(crate) mod bacnet;
pub(crate) mod mms;
pub(crate) mod iec104;

pub use self::{dnp3::Dnp3Arg, modbus::ModbusArg, s7comm::S7CommArg};
use self::{fins::FinsArg, opcua::OpcuaArg, bacnet::BacnetArg, mms::MmsArg, iec104::IEC104Arg};

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
    OPCUA(OpcuaArg),
    BACNET(BacnetArg),
    MMS(MmsArg),
    IEC104(IEC104Arg)
}

impl IcsRuleDetector for IcsRuleArg {
    fn detect(&self, l5: &L5Packet) -> bool {
        match self {
            Self::Modbus(modbus_arg) => modbus_arg.detect(l5),
            Self::S7COMM(s7comm_arg) => s7comm_arg.detect(l5),
            Self::DNP3(dnp3_arg) => dnp3_arg.detect(l5),
            Self::FINS(fins_arg) => fins_arg.detect(l5),
            Self::OPCUA(opcua_arg) => opcua_arg.detect(l5),
            Self::BACNET(bacnet_arg) => bacnet_arg.detect(l5),
            Self::MMS(mms_arg) => mms_arg.detect(l5),
            Self::IEC104(iec104_arg) => iec104_arg.detect(l5)
        }
    }
}
