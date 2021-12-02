use parsing_parser::parsers::modbus_rsp;

use serde::{Serialize, Deserialize};


#[derive(Serialize, Deserialize, Debug)]
pub struct MbapHeader {
    pub transaction_id: Option<u16>,
    pub protocol_id: Option<u16>,
    pub length: Option<u16>,
    pub unit_id: Option<u8>,
}

impl MbapHeader {
    pub fn check_arg(&self, mbap_header: &modbus_rsp::MbapHeader) -> bool {
        if let Some(transaction_id) = self.transaction_id {
            if transaction_id != mbap_header.transaction_id {
                return false
            }
        }
        if let Some(protocol_id) = self.protocol_id {
            if protocol_id != mbap_header.protocol_id {
                return false
            }
        }
        if let Some(length) = self.length {
            if length != mbap_header.length {
                return false
            }
        }
        if let Some(unit_id) = self.unit_id {
            if unit_id != mbap_header.unit_id {
                return false
            }
        }
        
        true
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "function_code", content = "data")]
pub enum Data {
    #[serde(alias = "1", alias = "0x01")]
    ReadCoils {
        byte_count: Option<u8>,
    },
    #[serde(alias = "129", alias = "0x81")]
    ReadCoilsExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "2", alias = "0x02")]
    ReadDiscreteInputs {
        byte_count: Option<u8>,
    },
    #[serde(alias = "130", alias = "0x82")]
    ReadDiscreteInputsExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "3", alias = "0x03")]
    ReadHoldingRegisters {
        byte_count: Option<u8>,
    },
    #[serde(alias = "131", alias = "0x83")]
    ReadHoldingRegistersExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "4", alias = "0x04")]
    ReadInputRegisters {
        byte_count: Option<u8>,
    },
    #[serde(alias = "132", alias = "0x84")]
    ReadInputRegistersExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "5", alias = "0x05")]
    WriteSingleCoil {
        output_address: Option<u16>,
        output_value: Option<u16>,
    },
    #[serde(alias = "133", alias = "0x85")]
    WriteSingleCoilExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "6", alias = "0x06")]
    WriteSingleRegister {
        register_address: Option<u16>,
        register_value: Option<u16>,
    },
    #[serde(alias = "134", alias = "0x86")]
    WriteSingleRegisterExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "7", alias = "0x07")]
    ReadExceptionStatus {
        output_data: Option<u8>,
    },
    #[serde(alias = "11", alias = "0x0b")]
    GetCommEventCounter {
        status: Option<u16>,
        event_count: Option<u16>,
    },
    #[serde(alias = "12", alias = "0x0c")]
    GetCommEventLog {
        byte_count: Option<u8>,
        status: Option<u16>,
        event_count: Option<u16>,
        message_count: Option<u16>,
    },
    #[serde(alias = "15", alias = "0x0f")]
    WriteMultipleCoils {
        start_address: Option<u16>,
        output_count: Option<u16>,
    },
    #[serde(alias = "143", alias = "0x8f")]
    WriteMultipleCoilsExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "16", alias = "0x10")]
    WriteMultipleRegisters {
        start_address: Option<u16>,
        output_count: Option<u16>,
    },
    #[serde(alias = "144", alias = "0x90")]
    WriteMultipleRegistersExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "17", alias = "0x11")]
    ReportServerID {
        byte_count: Option<u8>,
    },
    #[serde(alias = "20", alias = "0x14")]
    ReadFileRecord {
        byte_count: Option<u8>,
    },
    #[serde(alias = "148", alias = "0x94")]
    ReadFileRecordExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "21", alias = "0x15")]
    WriteFileRecord {
        byte_count: Option<u8>,
    },
    #[serde(alias = "149", alias = "0x95")]
    WriteFileRecordExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "22", alias = "0x16")]
    MaskWriteRegister {
        ref_address: Option<u16>,
        and_mask: Option<u16>,
        or_mask: Option<u16>,
    },
    #[serde(alias = "150", alias = "0x96")]
    MaskWriteRegisterExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "23", alias = "0x17")]
    ReadWriteMultipleRegisters {
        byte_count: Option<u8>,
    },
    #[serde(alias = "151", alias = "0x97")]
    ReadWriteMultipleRegistersExc {
        exception_code: Option<u8>,
    },
    #[serde(alias = "24", alias = "0x18")]
    ReadFIFOQueue {
        byte_count: Option<u16>,
        fifo_count: Option<u16>,
    },
    #[serde(alias = "152", alias = "0x98")]
    ReadFIFOQueueExc {
        exception_code: Option<u8>,
    }
}

impl Data {
    pub fn check_arg(&self, data: &modbus_rsp::Data) -> bool {
        match self {
            Data::ReadCoils {byte_count} => {
                if let modbus_rsp::Data::ReadCoils {byte_count: _byte_count, .. } = &data {
                    if let Some(byte_count) = byte_count {
                        if byte_count != _byte_count {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::ReadCoilsExc {exception_code} => {
                if let modbus_rsp::Data::ReadCoilsExc {exception_code: _exception_code, .. } = &data {
                    if let Some(exception_code) = exception_code {
                        if exception_code != _exception_code {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::ReadDiscreteInputs {byte_count} => {
                if let modbus_rsp::Data::ReadDiscreteInputs {byte_count: _byte_count, .. } = &data {
                    if let Some(byte_count) = byte_count {
                        if byte_count != _byte_count {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::ReadDiscreteInputsExc {exception_code} => {
                if let modbus_rsp::Data::ReadDiscreteInputsExc {exception_code: _exception_code, .. } = &data {
                    if let Some(exception_code) = exception_code {
                        if exception_code != _exception_code {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::ReadHoldingRegisters {byte_count} => {
                if let modbus_rsp::Data::ReadHoldingRegisters {byte_count: _byte_count, .. } = &data {
                    if let Some(byte_count) = byte_count {
                        if byte_count != _byte_count {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::ReadHoldingRegistersExc {exception_code} => {
                if let modbus_rsp::Data::ReadHoldingRegistersExc {exception_code: _exception_code, .. } = &data {
                    if let Some(exception_code) = exception_code {
                        if exception_code != _exception_code {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::ReadInputRegisters {byte_count} => {
                if let modbus_rsp::Data::ReadInputRegisters {byte_count: _byte_count, .. } = &data {
                    if let Some(byte_count) = byte_count {
                        if byte_count != _byte_count {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::ReadInputRegistersExc {exception_code} => {
                if let modbus_rsp::Data::ReadInputRegistersExc {exception_code: _exception_code, .. } = &data {
                    if let Some(exception_code) = exception_code {
                        if exception_code != _exception_code {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::WriteSingleCoil {output_address, output_value} => {
                if let modbus_rsp::Data::WriteSingleCoil {output_address: _output_address, output_value: _output_value, .. } = &data {
                    if let Some(output_address) = output_address {
                        if output_address != _output_address {
                            return false
                        }
                    }
                    if let Some(output_value) = output_value {
                        if output_value != _output_value {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::WriteSingleCoilExc {exception_code} => {
                if let modbus_rsp::Data::WriteSingleCoilExc {exception_code: _exception_code, .. } = &data {
                    if let Some(exception_code) = exception_code {
                        if exception_code != _exception_code {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::WriteSingleRegister {register_address, register_value} => {
                if let modbus_rsp::Data::WriteSingleRegister {register_address: _register_address, register_value: _register_value, .. } = &data {
                    if let Some(register_address) = register_address {
                        if register_address != _register_address {
                            return false
                        }
                    }
                    if let Some(register_value) = register_value {
                        if register_value != _register_value {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::WriteSingleRegisterExc {exception_code} => {
                if let modbus_rsp::Data::WriteSingleRegisterExc {exception_code: _exception_code, .. } = &data {
                    if let Some(exception_code) = exception_code {
                        if exception_code != _exception_code {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::ReadExceptionStatus {output_data} => {
                if let modbus_rsp::Data::ReadExceptionStatus {output_data: _output_data, .. } = &data {
                    if let Some(output_data) = output_data {
                        if output_data != _output_data {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::GetCommEventCounter {status, event_count} => {
                if let modbus_rsp::Data::GetCommEventCounter {status: _status, event_count: _event_count, .. } = &data {
                    if let Some(status) = status {
                        if status != _status {
                            return false
                        }
                    }
                    if let Some(event_count) = event_count {
                        if event_count != _event_count {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::GetCommEventLog {byte_count, status, event_count, message_count} => {
                if let modbus_rsp::Data::GetCommEventLog {byte_count: _byte_count, status: _status, event_count: _event_count, message_count: _message_count, .. } = &data {
                    if let Some(byte_count) = byte_count {
                        if byte_count != _byte_count {
                            return false
                        }
                    }
                    if let Some(status) = status {
                        if status != _status {
                            return false
                        }
                    }
                    if let Some(event_count) = event_count {
                        if event_count != _event_count {
                            return false
                        }
                    }
                    if let Some(message_count) = message_count {
                        if message_count != _message_count {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::WriteMultipleCoils {start_address, output_count} => {
                if let modbus_rsp::Data::WriteMultipleCoils {start_address: _start_address, output_count: _output_count, .. } = &data {
                    if let Some(start_address) = start_address {
                        if start_address != _start_address {
                            return false
                        }
                    }
                    if let Some(output_count) = output_count {
                        if output_count != _output_count {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::WriteMultipleCoilsExc {exception_code} => {
                if let modbus_rsp::Data::WriteMultipleCoilsExc {exception_code: _exception_code, .. } = &data {
                    if let Some(exception_code) = exception_code {
                        if exception_code != _exception_code {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::WriteMultipleRegisters {start_address, output_count} => {
                if let modbus_rsp::Data::WriteMultipleRegisters {start_address: _start_address, output_count: _output_count, .. } = &data {
                    if let Some(start_address) = start_address {
                        if start_address != _start_address {
                            return false
                        }
                    }
                    if let Some(output_count) = output_count {
                        if output_count != _output_count {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::WriteMultipleRegistersExc {exception_code} => {
                if let modbus_rsp::Data::WriteMultipleRegistersExc {exception_code: _exception_code, .. } = &data {
                    if let Some(exception_code) = exception_code {
                        if exception_code != _exception_code {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::ReportServerID {byte_count} => {
                if let modbus_rsp::Data::ReportServerID {byte_count: _byte_count, .. } = &data {
                    if let Some(byte_count) = byte_count {
                        if byte_count != _byte_count {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::ReadFileRecord {byte_count} => {
                if let modbus_rsp::Data::ReadFileRecord {byte_count: _byte_count, .. } = &data {
                    if let Some(byte_count) = byte_count {
                        if byte_count != _byte_count {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::ReadFileRecordExc {exception_code} => {
                if let modbus_rsp::Data::ReadFileRecordExc {exception_code: _exception_code, .. } = &data {
                    if let Some(exception_code) = exception_code {
                        if exception_code != _exception_code {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::WriteFileRecord {byte_count} => {
                if let modbus_rsp::Data::WriteFileRecord {byte_count: _byte_count, .. } = &data {
                    if let Some(byte_count) = byte_count {
                        if byte_count != _byte_count {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::WriteFileRecordExc {exception_code} => {
                if let modbus_rsp::Data::WriteFileRecordExc {exception_code: _exception_code, .. } = &data {
                    if let Some(exception_code) = exception_code {
                        if exception_code != _exception_code {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::MaskWriteRegister {ref_address, and_mask, or_mask} => {
                if let modbus_rsp::Data::MaskWriteRegister {ref_address: _ref_address, and_mask: _and_mask, or_mask: _or_mask, .. } = &data {
                    if let Some(ref_address) = ref_address {
                        if ref_address != _ref_address {
                            return false
                        }
                    }
                    if let Some(and_mask) = and_mask {
                        if and_mask != _and_mask {
                            return false
                        }
                    }
                    if let Some(or_mask) = or_mask {
                        if or_mask != _or_mask {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::MaskWriteRegisterExc {exception_code} => {
                if let modbus_rsp::Data::MaskWriteRegisterExc {exception_code: _exception_code, .. } = &data {
                    if let Some(exception_code) = exception_code {
                        if exception_code != _exception_code {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::ReadWriteMultipleRegisters {byte_count} => {
                if let modbus_rsp::Data::ReadWriteMultipleRegisters {byte_count: _byte_count, .. } = &data {
                    if let Some(byte_count) = byte_count {
                        if byte_count != _byte_count {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::ReadWriteMultipleRegistersExc {exception_code} => {
                if let modbus_rsp::Data::ReadWriteMultipleRegistersExc {exception_code: _exception_code, .. } = &data {
                    if let Some(exception_code) = exception_code {
                        if exception_code != _exception_code {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::ReadFIFOQueue {byte_count, fifo_count} => {
                if let modbus_rsp::Data::ReadFIFOQueue {byte_count: _byte_count, fifo_count: _fifo_count, .. } = &data {
                    if let Some(byte_count) = byte_count {
                        if byte_count != _byte_count {
                            return false
                        }
                    }
                    if let Some(fifo_count) = fifo_count {
                        if fifo_count != _fifo_count {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
            Data::ReadFIFOQueueExc {exception_code} => {
                if let modbus_rsp::Data::ReadFIFOQueueExc {exception_code: _exception_code, .. } = &data {
                    if let Some(exception_code) = exception_code {
                        if exception_code != _exception_code {
                            return false
                        }
                    }
                } else {
                    return false
                }
            },
        }

        true
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PDU {
    #[serde(flatten)]
    pub data: Option<Data>
}

impl PDU {
    pub fn check_arg(&self, pdu: &modbus_rsp::PDU) -> bool {
        if let Some(data) = &self.data {
            if !data.check_arg(&pdu.data) {
                return false
            }
        }
        
        true
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ModbusRspArg {
    #[serde(flatten)]
    pub mbap_header: Option<MbapHeader>,
    #[serde(flatten)]
    pub pdu: Option<PDU>,
}

impl ModbusRspArg {
    pub fn check_arg(&self, modbus_rsp_header: &modbus_rsp::ModbusRspHeader) -> bool {
        if let Some(mbap_header) = &self.mbap_header {
            if !mbap_header.check_arg(&modbus_rsp_header.mbap_header) {
                return false
            }
        }
        if let Some(pdu) = &self.pdu {
            if !pdu.check_arg(&modbus_rsp_header.pdu) {
                return false
            }
        }
        
        true
    }
}