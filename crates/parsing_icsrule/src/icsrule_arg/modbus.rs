use crate::detect::IcsRuleDetector;
use parsing_parser::L5Packet;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "function_code")]
pub enum ModbusArg {
    #[serde(rename = "1", alias = "0x01")]
    ReadCoils {
        start_address: Option<u16>,
        end_address: Option<u16>
    },
    #[serde(alias = "2", alias = "0x02")]
    ReadDiscreteInputs {
        start_address: Option<u16>,
        end_address: Option<u16>
    },
    #[serde(alias = "3", alias = "0x03")]
    ReadHoldingRegisters {
        start_address: Option<u16>,
        end_address: Option<u16>
    },
    #[serde(alias = "4", alias = "0x04")]
    ReadInputRegisters {
        start_address: Option<u16>,
        end_address: Option<u16>
    },
    #[serde(rename = "5", alias = "0x05")]
    WriteSingleCoil {
        start_address: Option<u16>,
        end_address: Option<u16>,
        value: Option<u8>
    },
    #[serde(rename = "6", alias = "0x06")]
    WriteSingleRegister {
        start_address: Option<u16>,
        end_address: Option<u16>,
        value: Option<u16>
    },
    #[serde(rename = "8", alias = "0x08")]
    Diagnostics {
        subfunction: Option<u8>
    },
    #[serde(rename = "12", alias = "0x0c", alias = "0x0C")]
    GetCommEventLog {},
    #[serde(rename = "15", alias = "0x0f", alias = "0x0F")]
    WriteMultipleCoils {
        start_address: Option<u16>,
        end_address: Option<u16>,
        value: Option<Vec<u8>> // 寄存器值(选填, 范围0~255, 列表数量不超过150)
    },
    #[serde(rename = "16", alias = "0x10")]
    WriteMultipleRegisters {
        start_address: Option<u16>,
        end_address: Option<u16>,
        value: Option<Vec<u16>>
    },
    #[serde(rename = "17", alias = "0x11")]
    ReportServerID {},
    #[serde(rename = "20", alias = "0x14")]
    ReadFileRecord {},
    #[serde(rename = "21", alias = "0x15")]
    WriteFileRecord {},
    #[serde(rename = "22", alias = "0x16")]
    MaskWriteRegister {
        start_address: Option<u16>,
        end_address: Option<u16>,
        and_mask: Option<u16>,
        or_mask: Option<u16>
    },
    #[serde(rename = "23", alias = "0x17")]
    ReadWriteMultipleRegisters {
        start_address1: Option<u16>,
        end_address1: Option<u16>,
        start_address2: Option<u16>,
        end_address2: Option<u16>,
        value: Option<Vec<u16>>
    },
    #[serde(rename = "24", alias = "0x18")]
    ReadFIFOQueue { 
        start_address: Option<u16>,
        end_address: Option<u16>
    },
    #[serde(rename = "43", alias = "0x2b", alias = "0x2B")]
    EncapsulatedInterfaceTransport {
        subfunction: Option<u8>
    },
    #[serde(other)]
    Unknow
}

impl IcsRuleDetector for ModbusArg {
    fn detect(&self, _l5: &L5Packet) -> bool {

        false
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, str::FromStr};

    use crate::{
        icsrule::basis::{Direction, Action},
        icsrule_arg::IcsRuleArg,
        IcsRuleBasis,
        IcsRule
    };

    use super::*;

    #[test]
    fn serialize_modbus_icsrule() {
        let modbus_rule = IcsRule {
            basic: IcsRuleBasis {
                active: true,
                rid: 1,
                action: Action::Alert,
                src_ip: Some(IpAddr::from_str("192.168.3.189").unwrap()),
                src_port: None,
                dir: Direction::Bi,
                dst_ip: None,
                dst_port: None,
                msg: "Modbus Read Coils(1)".to_string(),
            },
            args: IcsRuleArg::Modbus(
                ModbusArg::ReadCoils {
                    start_address: Some(0),
                    end_address: Some(10)
                }
            )
        };

        assert_eq!( 
            serde_json::to_string(&modbus_rule).unwrap(),
            r#"{"active":true,"rid":1,"action":"alert","src":"192.168.3.189","sport":null,"dire":"<>","dst":null,"dport":null,"msg":"Modbus Read Coils(1)","proname":"Modbus","args":{"function_code":"1","start_address":0,"end_address":10}}"#
        )
    }
}
