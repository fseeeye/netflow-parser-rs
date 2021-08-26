use serde::{Serialize, Deserialize};

use crate::parsers::ModbusRspHeader;
use crate::parsers::modbus_rsp;


#[derive(Serialize, Deserialize, Debug)]
pub struct ModbusRspArg {
    #[serde(flatten)]
    pub mbap_header: Option<MbapHeader>,
    #[serde(flatten)]
    pub pdu: Option<PDU>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MbapHeader {
    pub transaction_id: Option<u16>,
    pub protocol_id: Option<u16>,
    pub length: Option<u16>,
    pub unit_id: Option<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PDU {
    // pub function_code: Option<u8>,
    #[serde(flatten)]
    pub data: Option<Data>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "function", content = "data")]
pub enum Data {
    #[serde(alias = "1", alias = "0x01")]
    ReadCoils {
        byte_count: Option<u8>,
    },
    #[serde(alias = "2", alias = "0x02")]
    ReadDiscreteInputs {
        byte_count: Option<u8>,
    },
    #[serde(alias = "3", alias = "0x03")]
    ReadHoldingRegisters {
        byte_count: Option<u8>,
    },
    #[serde(alias = "4", alias = "0x04")]
    ReadInputRegisters {
        byte_count: Option<u8>,
    },
    #[serde(alias = "5", alias = "0x05")]
    WriteSingleCoil {
        output_address: Option<u16>,
        output_value: Option<u16>,
    },
    #[serde(alias = "6", alias = "0x06")]
    WriteSingleRegister {
        register_address: Option<u16>,
        register_value: Option<u16>,
    },
    #[serde(alias = "7", alias = "0x07")]
    ReadExceptionStatus {
        output_data: Option<u8>,
    },
    #[serde(alias = "11", alias = "0x0B")]
    GetCommEventCounter {
        status: Option<u16>,
        event_count: Option<u16>,
    },
    #[serde(alias = "12", alias = "0x0C")]
    GetCommEventLog {
        byte_count: Option<u8>,
        status: Option<u16>,
        event_count: Option<u16>,
        message_count: Option<u16>,
    },
    #[serde(alias = "15", alias = "0x0F")]
    WriteMultipleCoils {
        start_address: Option<u16>,
        output_count: Option<u16>,
    },
    #[serde(alias = "16", alias = "0x10")]
    WriteMultipleRegisters {
        start_address: Option<u16>,
        output_count: Option<u16>,
    },
    #[serde(alias = "17", alias = "0x11")]
    ReportServerID {
        byte_count: Option<u8>,
    },
    #[serde(alias = "20", alias = "0x14")]
    ReadFileRecord {
        byte_count: Option<u8>,
    },
    #[serde(alias = "21", alias = "0x15")]
    WriteFileRecord {
        byte_count: Option<u8>,
    },
    #[serde(alias = "22", alias = "0x16")]
    MaskWriteRegister {
        ref_address: Option<u16>,
        and_mask: Option<u16>,
        or_mask: Option<u16>,
    },
    #[serde(alias = "23", alias = "0x17")]
    ReadWriteMultipleRegisters {
        byte_count: Option<u8>,
    },
    #[serde(alias = "24", alias = "0x18")]
    ReadFIFOQueue {
        byte_count: Option<u16>,
        fifo_count: Option<u16>,
    },
    #[serde(alias = "129", alias = "0x81")]
    ReadCoilsExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "130", alias = "0x82")]
    ReadDiscreteInputsExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "131", alias = "0x83")]
    ReadHoldingRegistersExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "132", alias = "0x84")]
    ReadInputRegistersExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "133", alias = "0x85")]
    WriteSingleCoilExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "134", alias = "0x86")]
    WriteSingleRegisterExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "135", alias = "0x87")]
    ReadExceptionStatusExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "139", alias = "0x8B")]
    GetCommEventCounterExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "140", alias = "0x8C")]
    GetCommEventLogExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "143", alias = "0x8F")]
    WriteMultipleCoilsExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "144", alias = "0x90")]
    WriteMultipleRegistersExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "145", alias = "0x91")]
    ReportServerIDExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "148", alias = "0x94")]
    ReadFileRecordExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "149", alias = "0x95")]
    WriteFileRecordExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "150", alias = "0x96")]
    MaskWriteRegisterExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "151", alias = "0x97")]
    ReadWriteMultipleRegistersExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "152", alias = "0x98")]
    ReadFIFOQueueExc {
        exception_code: Option<u8>,
    },
}

impl ModbusRspArg {
    pub fn check_arg(&self, header: &ModbusRspHeader) -> bool {
        let packet_mbap_header = &header.mbap_header;
        if let Some(mbap_header) = &self.mbap_header {
            if let Some(transaction_id) = &mbap_header.transaction_id {
                if transaction_id != &packet_mbap_header.transaction_id {
                    return false;
                }
            }
            if let Some(protocol_id) = &mbap_header.protocol_id {
                if protocol_id != &packet_mbap_header.protocol_id {
                    return false;
                }
            }
            if let Some(length) = &mbap_header.length {
                if length != &packet_mbap_header.length {
                    return false;
                }
            }
            if let Some(unit_id) = &mbap_header.unit_id {
                if unit_id != &packet_mbap_header.unit_id {
                    return false;
                }
            }
        }

        if let Some(pdu) = &self.pdu {
            if let Some(data) = &pdu.data {
                match data {
                    Data::ReadCoils {byte_count} => {
                        if let modbus_rsp::Data::ReadCoils { byte_count: _byte_count, .. } = &header.pdu.data {
                            if let Some(byte_count) = byte_count {
                                if byte_count != _byte_count {
                                    return false;
                                }
                            }
                        } else {
                            // 如果enum类型不相符，则直接返回false
                            return false;
                        }
                    },
                    Data::ReadDiscreteInputs {byte_count} => {
                        if let modbus_rsp::Data::ReadDiscreteInputs { byte_count: _byte_count, .. } = &header.pdu.data {
                            if let Some(byte_count) = byte_count {
                                if byte_count != _byte_count {
                                    return false;
                                }
                            }
                        } else {
                            return false;
                        }
                    },
                    _ => {
                        unimplemented!();
                    }
                }
            }
        }

        true
    }
}