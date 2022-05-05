use crate::{detect::IcsRuleDetector, detect_address};
use parsing_parser::{parsers::modbus_req, ApplicationLayer, L5Packet};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "function_code")]
pub enum ModbusArg {
    #[serde(rename = "1", alias = "0x01")]
    ReadCoils {
        start_address: Option<u16>,
        end_address: Option<u16>,
    },
    #[serde(alias = "2", alias = "0x02")]
    ReadDiscreteInputs {
        start_address: Option<u16>,
        end_address: Option<u16>,
    },
    #[serde(alias = "3", alias = "0x03")]
    ReadHoldingRegisters {
        start_address: Option<u16>,
        end_address: Option<u16>,
    },
    #[serde(alias = "4", alias = "0x04")]
    ReadInputRegisters {
        start_address: Option<u16>,
        end_address: Option<u16>,
    },
    #[serde(rename = "5", alias = "0x05")]
    WriteSingleCoil {
        start_address: Option<u16>,
        end_address: Option<u16>,
        value: Option<u8>,
    },
    #[serde(rename = "6", alias = "0x06")]
    WriteSingleRegister {
        start_address: Option<u16>,
        end_address: Option<u16>,
        value: Option<u16>,
    },
    #[serde(rename = "7", alias = "0x07")]
    ReadExceptionStatus {},
    #[serde(rename = "8", alias = "0x08")]
    Diagnostics { subfunction: Option<u8> },
    #[serde(rename = "11", alias = "0x11")]
    GetCommEventCounter {},
    #[serde(rename = "12", alias = "0x0c", alias = "0x0C")]
    GetCommEventLog {},
    #[serde(rename = "15", alias = "0x0f", alias = "0x0F")]
    WriteMultipleCoils {
        start_address: Option<u16>,
        end_address: Option<u16>,
        value: Option<Vec<u8>>, // 寄存器值(选填, 范围0~255, 列表数量不超过150)
    },
    #[serde(rename = "16", alias = "0x10")]
    WriteMultipleRegisters {
        start_address: Option<u16>,
        end_address: Option<u16>,
        value: Option<Vec<u16>>,
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
        or_mask: Option<u16>,
    },
    #[serde(rename = "23", alias = "0x17")]
    ReadWriteMultipleRegisters {
        start_address: Option<u16>,
        end_address: Option<u16>,
        start_address2: Option<u16>,
        end_address2: Option<u16>,
        value: Option<Vec<u16>>,
    },
    #[serde(rename = "24", alias = "0x18")]
    ReadFIFOQueue {
        start_address: Option<u16>,
        end_address: Option<u16>,
    },
    #[serde(rename = "43", alias = "0x2b", alias = "0x2B")]
    EncapsulatedInterfaceTransport { subfunction: Option<u8> },
    #[serde(other)]
    Unknow,
}

impl IcsRuleDetector for ModbusArg {
    fn detect(&self, l5: &L5Packet) -> bool {
        match &l5.application_layer {
            ApplicationLayer::ModbusReq(modbus_req_header) => {
                match self {
                    ModbusArg::ReadCoils {
                        start_address,
                        end_address,
                    } => {
                        if let modbus_req::Data::ReadCoils {
                            start_address: _start_address,
                            count: _count,
                        } = &modbus_req_header.pdu.data
                        {
                            detect_address!(start_address, end_address, _start_address);
                        } else {
                            return false;
                        }
                    }
                    ModbusArg::ReadDiscreteInputs {
                        start_address,
                        end_address,
                    } => {
                        if let modbus_req::Data::ReadDiscreteInputs {
                            start_address: _start_address,
                            count: _count,
                        } = &modbus_req_header.pdu.data
                        {
                            detect_address!(start_address, end_address, _start_address);
                        } else {
                            return false;
                        }
                    }
                    ModbusArg::ReadHoldingRegisters {
                        start_address,
                        end_address,
                    } => {
                        if let modbus_req::Data::ReadHoldingRegisters {
                            start_address: _start_address,
                            count: _count,
                        } = &modbus_req_header.pdu.data
                        {
                            detect_address!(start_address, end_address, _start_address);
                        } else {
                            return false;
                        }
                    }
                    ModbusArg::ReadInputRegisters {
                        start_address,
                        end_address,
                    } => {
                        if let modbus_req::Data::ReadInputRegisters {
                            start_address: _start_address,
                            count: _count,
                        } = &modbus_req_header.pdu.data
                        {
                            detect_address!(start_address, end_address, _start_address);
                        } else {
                            return false;
                        }
                    }
                    ModbusArg::WriteSingleCoil {
                        start_address,
                        end_address,
                        value,
                    } => {
                        if let modbus_req::Data::WriteSingleCoil {
                            output_address: _output_address,
                            output_value: _output_value,
                        } = &modbus_req_header.pdu.data
                        {
                            detect_address!(start_address, end_address, _output_address);

                            if let Some(value) = value {
                                if (*value) as u16 != *_output_value {
                                    return false;
                                }
                            }
                        } else {
                            return false;
                        }
                    }
                    ModbusArg::WriteSingleRegister {
                        start_address,
                        end_address,
                        value,
                    } => {
                        if let modbus_req::Data::WriteSingleRegister {
                            register_address: _register_address,
                            register_value: _register_value,
                        } = &modbus_req_header.pdu.data
                        {
                            detect_address!(start_address, end_address, _register_address);

                            if let Some(value) = value {
                                if value != _register_value {
                                    return false;
                                }
                            }
                        } else {
                            return false;
                        }
                    }
                    ModbusArg::ReadExceptionStatus {} => match &modbus_req_header.pdu.data {
                        modbus_req::Data::ReadExceptionStatus {} => {}
                        _ => return false,
                    },
                    ModbusArg::Diagnostics {
                        subfunction: _subfunction,
                    } => {
                        // TODO: impl Modbus Diagnostics parsing
                        return false;
                    }
                    ModbusArg::GetCommEventCounter {} => match &modbus_req_header.pdu.data {
                        modbus_req::Data::GetCommEventCounter {} => {}
                        _ => return false,
                    },
                    ModbusArg::GetCommEventLog {} => match &modbus_req_header.pdu.data {
                        modbus_req::Data::GetCommEventLog {} => {}
                        _ => return false,
                    },
                    ModbusArg::WriteMultipleCoils {
                        start_address,
                        end_address,
                        value,
                    } => {
                        if let modbus_req::Data::WriteMultipleCoils {
                            start_address: _start_address,
                            output_values: _output_values,
                            ..
                        } = &modbus_req_header.pdu.data
                        {
                            detect_address!(start_address, end_address, _start_address);

                            if let Some(value) = value {
                                let mut i: usize = 0;
                                for v in value {
                                    if let Some(_value) = _output_values.get(i) {
                                        if _value != v {
                                            return false;
                                        }
                                    } else {
                                        return false;
                                    }
                                    i += 1;
                                }
                            }
                        } else {
                            return false;
                        }
                    }
                    ModbusArg::WriteMultipleRegisters {
                        start_address,
                        end_address,
                        value,
                    } => {
                        if let modbus_req::Data::WriteMultipleRegisters {
                            start_address: _start_address,
                            output_values: _output_values,
                            ..
                        } = &modbus_req_header.pdu.data
                        {
                            detect_address!(start_address, end_address, _start_address);

                            if let Some(value) = value {
                                let mut i: usize = 0;
                                for v in value {
                                    if let Some(_value) = _output_values.get(i) {
                                        if _value != v {
                                            return false;
                                        }
                                    } else {
                                        return false;
                                    }
                                    i += 1;
                                }
                            }
                        } else {
                            return false;
                        }
                    }
                    ModbusArg::ReportServerID {} => match &modbus_req_header.pdu.data {
                        modbus_req::Data::ReportServerID {} => {}
                        _ => return false,
                    },
                    ModbusArg::ReadFileRecord {} => match &modbus_req_header.pdu.data {
                        modbus_req::Data::ReadFileRecord { .. } => {}
                        _ => return false,
                    },
                    ModbusArg::WriteFileRecord {} => match &modbus_req_header.pdu.data {
                        modbus_req::Data::WriteFileRecord { .. } => {}
                        _ => return false,
                    },
                    ModbusArg::MaskWriteRegister {
                        start_address,
                        end_address,
                        and_mask,
                        or_mask,
                    } => {
                        if let modbus_req::Data::MaskWriteRegister {
                            ref_address: _start_address,
                            and_mask: _and_mask,
                            or_mask: _or_mask,
                        } = &modbus_req_header.pdu.data
                        {
                            detect_address!(start_address, end_address, _start_address);

                            if let Some(and_mask) = and_mask {
                                if and_mask != _and_mask {
                                    return false;
                                }
                            }
                            if let Some(or_mask) = or_mask {
                                if or_mask != _or_mask {
                                    return false;
                                }
                            }
                        } else {
                            return false;
                        }
                    }
                    ModbusArg::ReadWriteMultipleRegisters {
                        start_address,
                        end_address,
                        start_address2,
                        end_address2,
                        value,
                    } => {
                        if let modbus_req::Data::ReadWriteMultipleRegisters {
                            read_start_address: _read_start_address,
                            write_start_address: _write_start_address,
                            write_register_values: _write_register_values,
                            ..
                        } = &modbus_req_header.pdu.data
                        {
                            detect_address!(start_address, end_address, _read_start_address);
                            detect_address!(start_address2, end_address2, _write_start_address);

                            if let Some(value) = value {
                                let mut i: usize = 0;
                                for v in value {
                                    if let Some(_value) = _write_register_values.get(i) {
                                        if _value != v {
                                            return false;
                                        }
                                    } else {
                                        return false;
                                    }
                                    i += 1;
                                }
                            }
                        } else {
                            return false;
                        }
                    }
                    ModbusArg::ReadFIFOQueue {
                        start_address,
                        end_address,
                    } => {
                        if let modbus_req::Data::ReadFIFOQueue {
                            fifo_pointer_address: _fifo_pointer_address,
                        } = &modbus_req_header.pdu.data
                        {
                            detect_address!(start_address, end_address, _fifo_pointer_address);
                        } else {
                            return false;
                        }
                    }
                    ModbusArg::EncapsulatedInterfaceTransport {
                        subfunction: _subfunction,
                    } => {
                        // TODO: impl Modbus EncapsulatedInterfaceTransport parsing
                        return false;
                    }
                    ModbusArg::Unknow => return false,
                };

                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, str::FromStr};

    use parsing_rule::{RuleAction, Direction};

    use crate::{
        icsrule_arg::IcsRuleArg,
        HmIcsRules, IcsRule, IcsRuleBasis, rule_utils::*,
    };

    use super::*;

    #[test]
    fn serialize_modbus_icsrule() {
        let modbus_rule = IcsRule {
            basic: IcsRuleBasis {
                active: true,
                rid: 1,
                action: RuleAction::Alert,
                src_ip: Some(Ipv4AddressVec(vec![Ipv4Address::Addr(Ipv4Addr::from_str("192.168.3.189").unwrap())])),
                src_port: None,
                dir: Direction::Bi,
                dst_ip: None,
                dst_port: None,
                msg: "Modbus Read Coils(1)".to_string(),
            },
            args: IcsRuleArg::Modbus(ModbusArg::ReadCoils {
                start_address: Some(0),
                end_address: Some(10),
            }),
        };

        assert_eq!(
            serde_json::to_string(&modbus_rule).unwrap(),
            r#"{"active":true,"rid":1,"action":"alert","src":["192.168.3.189"],"sport":null,"dire":"<>","dst":null,"dport":null,"msg":"Modbus Read Coils(1)","proname":"Modbus","args":{"function_code":"1","start_address":0,"end_address":10}}"#
        )
    }

    #[test]
    fn deserialize_modbus_icsrule() {
        let mut ics_rules = HmIcsRules::new();
        let file_str = "./tests/unitest_modbus.json";
        assert!(ics_rules.load_rules(file_str));
    }
}
