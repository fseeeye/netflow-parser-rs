use parsing_parser::parsers::modbus_req;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct MbapHeader {
    pub transaction_id: Option<u16>,
    pub protocol_id: Option<u16>,
    pub length: Option<u16>,
    pub unit_id: Option<u8>,
}

impl MbapHeader {
    pub fn check_arg(&self, mbap_header: &modbus_req::MbapHeader) -> bool {
        if let Some(transaction_id) = self.transaction_id {
            if transaction_id != mbap_header.transaction_id {
                return false;
            }
        }
        if let Some(protocol_id) = self.protocol_id {
            if protocol_id != mbap_header.protocol_id {
                return false;
            }
        }
        if let Some(length) = self.length {
            if length != mbap_header.length {
                return false;
            }
        }
        if let Some(unit_id) = self.unit_id {
            if unit_id != mbap_header.unit_id {
                return false;
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
        start_address: Option<u16>,
        count: Option<u16>,
    },
    #[serde(alias = "2", alias = "0x02")]
    ReadDiscreteInputs {
        start_address: Option<u16>,
        count: Option<u16>,
    },
    #[serde(alias = "3", alias = "0x03")]
    ReadHoldingRegisters {
        start_address: Option<u16>,
        count: Option<u16>,
    },
    #[serde(alias = "4", alias = "0x04")]
    ReadInputRegisters {
        start_address: Option<u16>,
        count: Option<u16>,
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
    ReadExceptionStatus {},
    #[serde(alias = "11", alias = "0x0b")]
    GetCommEventCounter {},
    #[serde(alias = "12", alias = "0x0c")]
    GetCommEventLog {},
    #[serde(alias = "15", alias = "0x0f")]
    WriteMultipleCoils {
        start_address: Option<u16>,
        output_count: Option<u16>,
        byte_count: Option<u8>,
    },
    #[serde(alias = "16", alias = "0x10")]
    WriteMultipleRegisters {
        start_address: Option<u16>,
        output_count: Option<u16>,
        byte_count: Option<u8>,
    },
    #[serde(alias = "17", alias = "0x11")]
    ReportServerID {},
    #[serde(alias = "20", alias = "0x14")]
    ReadFileRecord { byte_count: Option<u8> },
    #[serde(alias = "21", alias = "0x15")]
    WriteFileRecord { byte_count: Option<u8> },
    #[serde(alias = "22", alias = "0x16")]
    MaskWriteRegister {
        ref_address: Option<u16>,
        and_mask: Option<u16>,
        or_mask: Option<u16>,
    },
    #[serde(alias = "23", alias = "0x17")]
    ReadWriteMultipleRegisters {
        read_start_address: Option<u16>,
        read_count: Option<u16>,
        write_start_address: Option<u16>,
        write_count: Option<u16>,
        write_byte_count: Option<u8>,
    },
    #[serde(alias = "24", alias = "0x18")]
    ReadFIFOQueue { fifo_pointer_address: Option<u16> },
}

impl Data {
    pub fn check_arg(&self, data: &modbus_req::Data) -> bool {
        match self {
            Data::ReadCoils {
                start_address,
                count,
            } => {
                if let modbus_req::Data::ReadCoils {
                    start_address: _start_address,
                    count: _count,
                    ..
                } = &data
                {
                    if let Some(start_address) = start_address {
                        if start_address != _start_address {
                            return false;
                        }
                    }
                    if let Some(count) = count {
                        if count != _count {
                            return false;
                        }
                    }
                } else {
                    return false;
                }
            }
            Data::ReadDiscreteInputs {
                start_address,
                count,
            } => {
                if let modbus_req::Data::ReadDiscreteInputs {
                    start_address: _start_address,
                    count: _count,
                    ..
                } = &data
                {
                    if let Some(start_address) = start_address {
                        if start_address != _start_address {
                            return false;
                        }
                    }
                    if let Some(count) = count {
                        if count != _count {
                            return false;
                        }
                    }
                } else {
                    return false;
                }
            }
            Data::ReadHoldingRegisters {
                start_address,
                count,
            } => {
                if let modbus_req::Data::ReadHoldingRegisters {
                    start_address: _start_address,
                    count: _count,
                    ..
                } = &data
                {
                    if let Some(start_address) = start_address {
                        if start_address != _start_address {
                            return false;
                        }
                    }
                    if let Some(count) = count {
                        if count != _count {
                            return false;
                        }
                    }
                } else {
                    return false;
                }
            }
            Data::ReadInputRegisters {
                start_address,
                count,
            } => {
                if let modbus_req::Data::ReadInputRegisters {
                    start_address: _start_address,
                    count: _count,
                    ..
                } = &data
                {
                    if let Some(start_address) = start_address {
                        if start_address != _start_address {
                            return false;
                        }
                    }
                    if let Some(count) = count {
                        if count != _count {
                            return false;
                        }
                    }
                } else {
                    return false;
                }
            }
            Data::WriteSingleCoil {
                output_address,
                output_value,
            } => {
                if let modbus_req::Data::WriteSingleCoil {
                    output_address: _output_address,
                    output_value: _output_value,
                    ..
                } = &data
                {
                    if let Some(output_address) = output_address {
                        if output_address != _output_address {
                            return false;
                        }
                    }
                    if let Some(output_value) = output_value {
                        if output_value != _output_value {
                            return false;
                        }
                    }
                } else {
                    return false;
                }
            }
            Data::WriteSingleRegister {
                register_address,
                register_value,
            } => {
                if let modbus_req::Data::WriteSingleRegister {
                    register_address: _register_address,
                    register_value: _register_value,
                    ..
                } = &data
                {
                    if let Some(register_address) = register_address {
                        if register_address != _register_address {
                            return false;
                        }
                    }
                    if let Some(register_value) = register_value {
                        if register_value != _register_value {
                            return false;
                        }
                    }
                } else {
                    return false;
                }
            }
            Data::ReadExceptionStatus {} => match data {
                modbus_req::Data::ReadExceptionStatus {} => {}
                _ => return false,
            },
            Data::GetCommEventCounter {} => match data {
                modbus_req::Data::GetCommEventCounter {} => {}
                _ => return false,
            },
            Data::GetCommEventLog {} => match data {
                modbus_req::Data::GetCommEventLog {} => {}
                _ => return false,
            },
            Data::WriteMultipleCoils {
                start_address,
                output_count,
                byte_count,
            } => {
                if let modbus_req::Data::WriteMultipleCoils {
                    start_address: _start_address,
                    output_count: _output_count,
                    byte_count: _byte_count,
                    ..
                } = &data
                {
                    if let Some(start_address) = start_address {
                        if start_address != _start_address {
                            return false;
                        }
                    }
                    if let Some(output_count) = output_count {
                        if output_count != _output_count {
                            return false;
                        }
                    }
                    if let Some(byte_count) = byte_count {
                        if byte_count != _byte_count {
                            return false;
                        }
                    }
                } else {
                    return false;
                }
            }
            Data::WriteMultipleRegisters {
                start_address,
                output_count,
                byte_count,
            } => {
                if let modbus_req::Data::WriteMultipleRegisters {
                    start_address: _start_address,
                    output_count: _output_count,
                    byte_count: _byte_count,
                    ..
                } = &data
                {
                    if let Some(start_address) = start_address {
                        if start_address != _start_address {
                            return false;
                        }
                    }
                    if let Some(output_count) = output_count {
                        if output_count != _output_count {
                            return false;
                        }
                    }
                    if let Some(byte_count) = byte_count {
                        if byte_count != _byte_count {
                            return false;
                        }
                    }
                } else {
                    return false;
                }
            }
            Data::ReportServerID {} => match data {
                modbus_req::Data::ReportServerID {} => {}
                _ => return false,
            },
            Data::ReadFileRecord { byte_count } => {
                if let modbus_req::Data::ReadFileRecord {
                    byte_count: _byte_count,
                    ..
                } = &data
                {
                    if let Some(byte_count) = byte_count {
                        if byte_count != _byte_count {
                            return false;
                        }
                    }
                } else {
                    return false;
                }
            }
            Data::WriteFileRecord { byte_count } => {
                if let modbus_req::Data::WriteFileRecord {
                    byte_count: _byte_count,
                    ..
                } = &data
                {
                    if let Some(byte_count) = byte_count {
                        if byte_count != _byte_count {
                            return false;
                        }
                    }
                } else {
                    return false;
                }
            }
            Data::MaskWriteRegister {
                ref_address,
                and_mask,
                or_mask,
            } => {
                if let modbus_req::Data::MaskWriteRegister {
                    ref_address: _ref_address,
                    and_mask: _and_mask,
                    or_mask: _or_mask,
                    ..
                } = &data
                {
                    if let Some(ref_address) = ref_address {
                        if ref_address != _ref_address {
                            return false;
                        }
                    }
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
            Data::ReadWriteMultipleRegisters {
                read_start_address,
                read_count,
                write_start_address,
                write_count,
                write_byte_count,
            } => {
                if let modbus_req::Data::ReadWriteMultipleRegisters {
                    read_start_address: _read_start_address,
                    read_count: _read_count,
                    write_start_address: _write_start_address,
                    write_count: _write_count,
                    write_byte_count: _write_byte_count,
                    ..
                } = &data
                {
                    if let Some(read_start_address) = read_start_address {
                        if read_start_address != _read_start_address {
                            return false;
                        }
                    }
                    if let Some(read_count) = read_count {
                        if read_count != _read_count {
                            return false;
                        }
                    }
                    if let Some(write_start_address) = write_start_address {
                        if write_start_address != _write_start_address {
                            return false;
                        }
                    }
                    if let Some(write_count) = write_count {
                        if write_count != _write_count {
                            return false;
                        }
                    }
                    if let Some(write_byte_count) = write_byte_count {
                        if write_byte_count != _write_byte_count {
                            return false;
                        }
                    }
                } else {
                    return false;
                }
            }
            Data::ReadFIFOQueue {
                fifo_pointer_address,
            } => {
                if let modbus_req::Data::ReadFIFOQueue {
                    fifo_pointer_address: _fifo_pointer_address,
                    ..
                } = &data
                {
                    if let Some(fifo_pointer_address) = fifo_pointer_address {
                        if fifo_pointer_address != _fifo_pointer_address {
                            return false;
                        }
                    }
                } else {
                    return false;
                }
            }
        }

        true
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PDU {
    #[serde(flatten)]
    pub data: Option<Data>,
}

impl PDU {
    pub fn check_arg(&self, pdu: &modbus_req::PDU) -> bool {
        if let Some(data) = &self.data {
            if !data.check_arg(&pdu.data) {
                return false;
            }
        }

        true
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ModbusReqArg {
    #[serde(flatten)]
    pub mbap_header: Option<MbapHeader>,
    #[serde(flatten)]
    pub pdu: Option<PDU>,
}

impl ModbusReqArg {
    pub fn check_arg(&self, modbus_req_header: &modbus_req::ModbusReqHeader) -> bool {
        if let Some(mbap_header) = &self.mbap_header {
            if !mbap_header.check_arg(&modbus_req_header.mbap_header) {
                return false;
            }
        }
        if let Some(pdu) = &self.pdu {
            if !pdu.check_arg(&modbus_req_header.pdu) {
                return false;
            }
        }

        true
    }
}
