use std::ffi::CString;

use libc::c_char;
use parsing_parser::{parsers::{
    BacnetHeader, bacnet::BvlcTypeInfo, 
    OpcuaHeader, opcua::{MessageTypeEnum, MsgVariantInfo, ServiceNodeidInfo}, 
    Iec104Header, iec104::{TypeBlock, IecAsdu}, 
    ModbusReqHeader, modbus_req, 
    S7commHeader, s7comm, Dnp3Header, FinsTcpReqHeader, fins_tcp_req
}, QuinPacket, LinkLayer, AppLevel, TransportLayer, NetworkLayer, TransLevel, ApplicationLayer, NetLevel, LinkLevel};

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ParsingReport {
    #[serde(rename = "match", default = "u8::default")]
    pub is_match: u8,
    pub timestamp: i64,
    #[serde(rename = "target")]
    pub alert_target: u8, // match_info->target
    #[serde(rename = "type")]
    pub alert_type: u8, // match_info->type
    pub direction: u8, // packet_info->dire
    #[serde(skip_serializing_if = "is_default")]
    pub smac: Option<String>,
    #[serde(skip_serializing_if = "is_default")]
    pub dmac: Option<String>,
    #[serde(skip_serializing_if = "is_default")]
    pub src: Option<String>,
    #[serde(skip_serializing_if = "is_default")]
    pub dst: Option<String>,
    #[serde(skip_serializing_if = "is_default")]
    pub sport: Option<u16>,
    #[serde(skip_serializing_if = "is_default")]
    pub dport: Option<u16>,
    #[serde(skip_serializing_if = "is_default")]
    pub proto: String,
    #[serde(skip_serializing_if = "is_default")]
    pub tran: Option<String>, // level4 or 5
    #[serde(skip_serializing_if = "is_default")]
    pub len: usize, // packet_info->tot_len
    #[serde(skip_serializing_if = "is_default")]
    pub payload: Option<String>, // ?
    #[serde(skip_serializing_if = "is_default")]
    pub fields: Option<ReportFields>
}

/// 获得解析结果(json)
#[no_mangle]
pub extern "C" fn get_parsing_json_rs(packet_ptr: *const QuinPacket, is_match: bool, alert_target: u8, alert_type: u8, direction: u8, packet_len: usize) -> *mut c_char {
    let make_empty_str = || CString::new("".to_string()).unwrap().into_raw();

    if packet_ptr.is_null() {
        tracing::warn!("Packet free: packet ptr is null!");
        return make_empty_str();
    }
    let packet = unsafe { &*packet_ptr };

    let mut report = ParsingReport::default();

    report.is_match = if is_match { 1 } else { 0 };
    report.timestamp = chrono::Local::now().timestamp();
    report.alert_target = alert_target;
    report.alert_type = alert_type;
    report.direction = direction;

    match packet {
        QuinPacket::L1(_l1) => {}
        QuinPacket::L2(l2) => {
            // mac
            let LinkLayer::Ethernet(eth) = &l2.link_layer;
            report.smac = Some(eth.src_mac.to_string());
            report.dmac = Some(eth.dst_mac.to_string());
            // proto name
            report.proto = l2.get_link_type().to_string();
        }
        QuinPacket::L3(l3) => {
            // mac
            let LinkLayer::Ethernet(eth) = &l3.link_layer;
            report.smac = Some(eth.src_mac.to_string());
            report.dmac = Some(eth.dst_mac.to_string());
            // ip
            if let NetworkLayer::Ipv4(ipv4) = &l3.network_layer {
                report.src = Some(ipv4.src_ip.to_string());
                report.dst = Some(ipv4.dst_ip.to_string());
            }
            // proto name
            report.proto = l3.get_net_type().to_string();
        }
        QuinPacket::L4(l4) => {
            // mac
            let LinkLayer::Ethernet(eth) = &l4.link_layer;
            report.smac = Some(eth.src_mac.to_string());
            report.dmac = Some(eth.dst_mac.to_string());
            // ip
            if let NetworkLayer::Ipv4(ipv4) = &l4.network_layer {
                report.src = Some(ipv4.src_ip.to_string());
                report.dst = Some(ipv4.dst_ip.to_string());
            }
            // port
            match &l4.transport_layer {
                TransportLayer::Udp(udp) => {
                    report.sport = Some(udp.src_port);
                    report.dport = Some(udp.dst_port);
                }
                TransportLayer::Tcp(tcp) => {
                    report.sport = Some(tcp.src_port);
                    report.dport = Some(tcp.dst_port);
                }
                _ => {}
            }
            // proto name
            report.proto = l4.get_net_type().to_string();
            // tran name
            report.tran = Some(report.proto.clone());
        }
        QuinPacket::L5(l5) => {
            // mac
            let LinkLayer::Ethernet(eth) = &l5.link_layer;
            report.smac = Some(eth.src_mac.to_string());
            report.dmac = Some(eth.dst_mac.to_string());
            // ip
            if let NetworkLayer::Ipv4(ipv4) = &l5.network_layer {
                report.src = Some(ipv4.src_ip.to_string());
                report.dst = Some(ipv4.dst_ip.to_string());
            }
            // port
            match &l5.transport_layer {
                TransportLayer::Udp(udp) => {
                    report.sport = Some(udp.src_port);
                    report.dport = Some(udp.dst_port);
                }
                TransportLayer::Tcp(tcp) => {
                    report.sport = Some(tcp.src_port);
                    report.dport = Some(tcp.dst_port);
                }
                _ => {}
            }
            // proto name
            report.proto = l5.get_app_naive_type().to_string();
            // tran name
            report.tran = Some(l5.get_tran_type().to_string());
            // fields json
            report.fields = Some(ReportFields::create(&l5.application_layer));
        }
    }

    report.len = packet_len;

    let json = match serde_json::to_string(&report) {
        Ok(o) => o,
        Err(_) => {
            tracing::warn!("Occurs error when report to string. returning empty.");
            return make_empty_str()
        }
    };

    tracing::trace!("Parsing Result Json: {}", json);

    match CString::new(json) {
        Ok(o) => o.into_raw(),
        Err(_) => {
            tracing::warn!("Occurs error when creating cstring from json. returning empty.");
            make_empty_str()
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum ReportFields {
    Bacnet(BacnetFields),
    Opcua(OpcuaFields),
    Iec104(Iec104Fields),
    Modbus(ModbusFields),
    S7Comm(S7commFields),
    Dnp3(Dnp3Fields),
    Fins(FinsFields),
    Empty
}

impl Default for ReportFields {
    fn default() -> Self {
        ReportFields::Empty
    }
}

impl ReportFields {
    fn create(app_layer : &ApplicationLayer) -> Self {
        match app_layer {
            ApplicationLayer::Bacnet(bacnet) => bacnet.get_fields(),
            ApplicationLayer::Opcua(opcua) => opcua.get_fields(),
            ApplicationLayer::Iec104(iec104) => iec104.get_fields(),
            ApplicationLayer::ModbusReq(modbus_req) => modbus_req.get_fields(),
            ApplicationLayer::S7comm(s7comm) => s7comm.get_fields(),
            ApplicationLayer::Dnp3(dnp3) => dnp3.get_fields(),
            ApplicationLayer::FinsTcpReq(fins) => fins.get_fields(),
            _ => ReportFields::Empty
        }
    }
}

// utils
trait ProtocolFields {
    fn get_fields(&self) -> ReportFields;
}

#[allow(dead_code)]
fn is_default<T>(val: &T) -> bool
where
T: Default + PartialEq,
{
    (*val) == T::default()
}

// BACnet
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct BacnetFields {
    #[serde(rename = "type")]
    pub bvlc_type: u8,
    #[serde(rename = "function_code")]
    pub bvlc_function: u8
}

impl<'a> ProtocolFields for BacnetHeader<'a> {
    fn get_fields(&self) -> ReportFields {
        let fields = BacnetFields {
            bvlc_type: self.bvlc.bvlc_type,
            bvlc_function:  match self.bvlc.bvlc_type_info {
                BvlcTypeInfo::Ipv4AnnexJ { bvlc_function, .. } => bvlc_function,
                BvlcTypeInfo::Ipv6AnnexU { bvlc_function, .. } => bvlc_function
            }
        };

        ReportFields::Bacnet(fields)
    }
}

// OpcUA
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct OpcuaFields {
    #[serde(rename = "type")]
    message_type: u32,
    #[serde(rename = "function_code", skip_serializing_if = "is_default")]
    service_nodeid_numeric: Option<u32>
}

impl<'a> ProtocolFields for OpcuaHeader<'a> {
    fn get_fields(&self) -> ReportFields {
        let fields = OpcuaFields {
            message_type: self.message_type,
            service_nodeid_numeric: match &self.message_type_enum {
                MessageTypeEnum::Message { 
                    msg_variant_info: MsgVariantInfo::Service { 
                        service_nodeid_info,
                        ..
                    }, 
                    .. 
                } => {
                    match service_nodeid_info {
                        ServiceNodeidInfo::TB { service_nodeid_numeric, .. } => Some(*service_nodeid_numeric as u32),
                        ServiceNodeidInfo::FB { service_nodeid_numeric, .. } => Some(*service_nodeid_numeric as u32),
                        ServiceNodeidInfo::Numeric { service_nodeid_numeric, .. } => Some(*service_nodeid_numeric),
                        _ => None
                    }
                }
                _ => None
            }
        };

        ReportFields::Opcua(fields)
    }
}

// IEC104
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(untagged)]
pub enum Iec104Fields {
    I {
        type104: u8,
        typeid: Vec<u8>,
        #[serde(rename = "cause")]
        cause_tx: Vec<u8>,
        addr: Vec<u16>
    },
    S {
        type104: u8,   
    },
    U {
        type104: u8,
        apci_utype: u8
    },
    Empty {}
}

impl ProtocolFields for Iec104Header {
    fn get_fields(&self) -> ReportFields {
        let mut fields = Iec104Fields::Empty {};

        for block in &self.iec104_blocks {
            match block.type_block {
                TypeBlock::TypeI { 
                    type104: _type104, 
                    iec_asdu: IecAsdu { type_id: _type_id, cause_tx: _cause_tx, addr: _addr, .. }, 
                    .. 
                } => {
                    if let Iec104Fields::I { typeid, cause_tx, addr, .. } = &mut fields {
                        typeid.push(_type_id);
                        cause_tx.push(_cause_tx);
                        addr.push(_addr);
                    } else {
                        fields = Iec104Fields::I {
                            type104: _type104,
                            typeid: vec![_type_id],
                            cause_tx: vec![_cause_tx],
                            addr: vec![_addr]
                        };
                    }
                }
                TypeBlock::TypeS { type104: _type104, .. } => {
                    fields = Iec104Fields::S { type104: _type104 };
                }
                TypeBlock::TypeU { type104: _type104, apci_utype: _apci_utype } => {
                    fields = Iec104Fields::U { type104: _type104, apci_utype: _apci_utype };
                }
            };
        }

        ReportFields::Iec104(fields)
    }
}

// Modbus
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct ModbusFields {
    function_code: u8,
    #[serde(skip_serializing_if = "is_default")]
    reference_num: Option<u16>,
    #[serde(skip_serializing_if = "is_default")]
    subfunction: Option<u8>
}

impl<'a> ProtocolFields for ModbusReqHeader<'a> {
    fn get_fields(&self) -> ReportFields {
        let fields = ModbusFields {
            function_code: self.pdu.function_code,
            reference_num: match self.pdu.data {
                modbus_req::Data::ReadCoils { start_address, .. } => Some(start_address),
                modbus_req::Data::ReadDiscreteInputs { start_address, .. } => Some(start_address),
                modbus_req::Data::ReadHoldingRegisters { start_address, .. } => Some(start_address),
                modbus_req::Data::ReadInputRegisters { start_address, .. } => Some(start_address),
                modbus_req::Data::WriteSingleCoil { output_address, .. } => Some(output_address),
                modbus_req::Data::WriteSingleRegister { register_address, .. } => Some(register_address),
                modbus_req::Data::WriteMultipleCoils { start_address, .. } => Some(start_address),
                modbus_req::Data::MaskWriteRegister { ref_address, .. } => Some(ref_address),
                // modbus_req::Data::ReadWriteMultipleRegisters { read_start_address, .. } => Some(read_start_address),
                modbus_req::Data::ReadFIFOQueue { fifo_pointer_address, .. } => Some(fifo_pointer_address),
                _ => None
            },
            subfunction: None // TODO: Diagnostics / EncapsulatedInterfaceTransport
        };

        ReportFields::Modbus(fields)
    }
}

// S7Comm
#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
pub struct S7commFields {
    rosctr: u8,
    function_code: Option<u8>,
    // address: Option<String>, // Job - ReadVar / Job - WriteVar ? List
    // value: Option<u32>, // Job - WriteVar / AckData - ReadVar ? List
    subfunction: Option<u8>, // Userdata
    parameter_type: Option<u8> // Userdata
}

impl<'a> ProtocolFields for S7commHeader<'a> {
    fn get_fields(&self) -> ReportFields {
        let mut fields = S7commFields::default();

        fields.rosctr = self.header.rosctr;

        match self.parameter {
            s7comm::Parameter::AckData { function_code, ackdata_param: _ } => {
                fields.function_code = Some(function_code);
            }
            s7comm::Parameter::Job { function_code, job_param: _ } => {
                fields.function_code = Some(function_code);
            }
            s7comm::Parameter::Userdata { parameter_type, function_group, subfunction, .. } => {
                fields.function_code = Some(function_group);
                fields.subfunction = Some(subfunction);
                fields.parameter_type = Some(parameter_type);
            }
            _ => {}
        };

        ReportFields::S7Comm(fields)
    }
}

// DNP3
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Dnp3Fields {
    primary: bool,
    link_function_code: u8,
    function_code: u8
}

impl ProtocolFields for Dnp3Header {
    fn get_fields(&self) -> ReportFields {
        let fields = Dnp3Fields {
            primary: if self.data_link_layer.dl_primary > 0 { true } else { false },
            link_function_code: self.data_link_layer.dl_function,
            function_code: self.application_layer.function_code
        };

        ReportFields::Dnp3(fields)
    }
}

// FINS
#[derive(Serialize, Deserialize, Debug, PartialEq, Default)]
pub struct FinsFields {
    function_code: Option<u16>,
    code: Option<u16>
}

impl<'a> ProtocolFields for FinsTcpReqHeader<'a> {
    fn get_fields(&self) -> ReportFields {
        let mut fields = FinsFields::default();

        if let fins_tcp_req::State::Connected { fh: fins_tcp_req::FH { cmd_type, ..} } = &self.state {
            fields.function_code = Some(cmd_type.cmd_code);

            match cmd_type.order {
                fins_tcp_req::Order::MemoryAreaRead { memory_area_code, .. } => { fields.code = Some(memory_area_code as u16) }
                fins_tcp_req::Order::MemoryAreaWrite { memory_area_code, .. } => { fields.code = Some(memory_area_code as u16) }
                fins_tcp_req::Order::MemoryAreaFill { memory_area_code, .. } => { fields.code = Some(memory_area_code as u16) }
                // fins_tcp_req::Order::MultipleMemoryAreaRead { rst, .. } => { }
                // fins_tcp_req::Order::MemoryAreaTransfer { memory_area_code_wc, .. } => { fields.code = Some(memory_area_code) }
                fins_tcp_req::Order::ParameterAreaRead { parameter_area_code, .. } => { fields.code = Some(parameter_area_code) }
                fins_tcp_req::Order::ParameterAreaWrite { parameter_area_code, .. } => { fields.code = Some(parameter_area_code) }
                fins_tcp_req::Order::ParameterAreaClear { parameter_area_code, .. } => { fields.code = Some(parameter_area_code) }
                fins_tcp_req::Order::Run { mode_code, .. } => { fields.code = Some(mode_code as u16) }
                fins_tcp_req::Order::MultipleForcedStatusRead { memory_area_code, .. } => { fields.code = Some(memory_area_code as u16) }
                _ => {}
            }
        }

        ReportFields::Fins(fields)
    }
}
