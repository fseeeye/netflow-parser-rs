use crate::parsers::ModbusReqHeader;
use crate::parsers::modbus_req;

use serde::{Serialize, Deserialize};


#[derive(Serialize, Deserialize, Debug)]
pub struct ModbusReqArg {
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
    // pub function_code: Option<u8>, // Q: if save it?
    #[serde(flatten)]
    pub data: Option<Data>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag="function", content="data")]
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
    #[serde(alias = "11", alias = "0x0B")]
    GetCommEventCounter {},
    #[serde(alias = "12", alias = "0x0C")]
    GetCommEventLog {},
    #[serde(alias = "15", alias = "0x0F")]
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
        read_start_address: Option<u16>,
        read_count: Option<u16>,
        write_start_address: Option<u16>,
        write_count: Option<u16>,
        write_byte_count: Option<u8>,
    },
    #[serde(alias = "24", alias = "0x18")]
    ReadFIFOQueue {
        fifo_pointer_address: Option<u16>,
    },
}

impl ModbusReqArg {
    pub fn check_arg(&self, header: &ModbusReqHeader) -> bool {
        if let Some(mbap_header) = &self.mbap_header {
            if let Some(transaction_id) = mbap_header.transaction_id {
                if transaction_id != header.mbap_header.transaction_id {
                    return false;
                }
            }
            if let Some(protocol_id) = mbap_header.protocol_id {
                if protocol_id != header.mbap_header.protocol_id {
                    return false;
                }
            }
            if let Some(length) = mbap_header.length {
                if length != header.mbap_header.length {
                    return false;
                }
            }
            if let Some(unit_id) = mbap_header.unit_id {
                if unit_id != header.mbap_header.unit_id {
                    return false;
                }
            }
        }

        if let Some(pdu) = &self.pdu {
            if let Some(data) = &pdu.data {
                match data {
                    Data::ReadCoils {start_address, count} => {
                        if let modbus_req::Data::ReadCoils { start_address: _start_address, count: _count, .. } = &header.pdu.data {
                            if let Some(start_address) = start_address {
                                if start_address != _start_address {
                                    return false
                                }
                            }
                            if let Some(count) = count {
                                if count != _count {
                                    return false
                                }
                            }
                        } else {
                            // 如果enum类型不相符，则直接返回false
                            return false;
                        }
                    },
                    Data::ReadDiscreteInputs {start_address, count} => {
                        if let modbus_req::Data::ReadDiscreteInputs { start_address: _start_address, count: _count, .. } = &header.pdu.data {
                            if let Some(start_address) = start_address {
                                if start_address != _start_address {
                                    return false
                                }
                            }
                            if let Some(count) = count {
                                if count != _count {
                                    return false
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