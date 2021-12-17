use std::{net::Ipv4Addr, str::FromStr};

use parsing_icsrule::HmIcsRules;
use parsing_parser::{parsers::{EthernetHeader, Ipv4Header, TcpHeader, ModbusRspHeader, ModbusReqHeader}, MacAddress, LinkLayer, NetworkLayer, TransportLayer, ApplicationLayer, L5Packet, QuinPacket};
use parsing_rule::{RulesDetector, DetectResult, RuleAction};


fn make_modbus_rsp_packet(rsp_pdu: parsing_parser::parsers::modbus_rsp::PDU) -> QuinPacket {
    let app_layer = ApplicationLayer::ModbusRsp( ModbusRspHeader {
        mbap_header: parsing_parser::parsers::modbus_rsp::MbapHeader {
            transaction_id: 0,
            protocol_id: 0,
            length: 0,
            unit_id: 0,
        },
        pdu: rsp_pdu,
    });

    let l5 = L5Packet {
        link_layer: LinkLayer::Ethernet(EthernetHeader {
            dst_mac: MacAddress([32, 16, 21, 233, 21, 1]),
            src_mac: MacAddress([32, 16, 21, 233, 21, 2]),
            link_type: 2048,
        }),
        network_layer: NetworkLayer::Ipv4(Ipv4Header {
            src_ip: Ipv4Addr::from_str("192.168.3.189").unwrap(),
            dst_ip: Ipv4Addr::from_str("192.168.3.190").unwrap(),
            version: 4,
            header_length: 5,
            diff_service: 0,
            ecn: 0,
            total_length: 131,
            id: 52555,
            flags: 2,
            fragment_offset: 0,
            ttl: 64,
            protocol: 6,
            checksum: 38996,
            options: None
        }),
        transport_layer: TransportLayer::Tcp(TcpHeader {
            src_port: 502,
            dst_port: 53211,
            seq: 1175987464,
            ack: 3947317609,
            header_length: 5,
            reserved: 0,
            flags: 24,
            window_size: 256,
            checksum: 45344,
            urgent_pointer: 0,
            options: None,
            payload: &[],
        }),
        application_layer: app_layer,
        remain: &[],
        error: None
    };

    return QuinPacket::L5(l5);
}

fn make_modbus_req_packet(req_pdu: parsing_parser::parsers::modbus_req::PDU) -> QuinPacket {
    let app_layer = ApplicationLayer::ModbusReq( ModbusReqHeader {
        mbap_header: parsing_parser::parsers::modbus_req::MbapHeader {
            transaction_id: 0,
            protocol_id: 0,
            length: 0,
            unit_id: 0,
        },
        pdu: req_pdu,
    });

    let l5 = L5Packet {
        link_layer: LinkLayer::Ethernet(EthernetHeader {
            dst_mac: MacAddress([32, 16, 21, 233, 21, 2]),
            src_mac: MacAddress([32, 16, 21, 233, 21, 1]),
            link_type: 2048,
        }),
        network_layer: NetworkLayer::Ipv4(Ipv4Header {
            src_ip: Ipv4Addr::from_str("192.168.3.190").unwrap(),
            dst_ip: Ipv4Addr::from_str("192.168.3.189").unwrap(),
            version: 4,
            header_length: 5,
            diff_service: 0,
            ecn: 0,
            total_length: 131,
            id: 52555,
            flags: 2,
            fragment_offset: 0,
            ttl: 64,
            protocol: 6,
            checksum: 38996,
            options: None
        }),
        transport_layer: TransportLayer::Tcp(TcpHeader {
            src_port: 53211,
            dst_port: 502,
            seq: 1175987464,
            ack: 3947317609,
            header_length: 5,
            reserved: 0,
            flags: 24,
            window_size: 256,
            checksum: 45344,
            urgent_pointer: 0,
            options: None,
            payload: &[],
        }),
        application_layer: app_layer,
        remain: &[],
        error: None
    };

    return QuinPacket::L5(l5);
}

#[test]
fn detect_modbus_read_discrete_inputs() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 1,
        data: parsing_parser::parsers::modbus_req::Data::ReadDiscreteInputs {
            start_address: 1,
            count: 1
        }
    };
    let packet_req = make_modbus_req_packet(req_pdu);

    let rsp_pdu = parsing_parser::parsers::modbus_rsp::PDU {
        function_code: 1,
        data: parsing_parser::parsers::modbus_rsp::Data::ReadDiscreteInputs {
            byte_count: 1,
            coil_status: vec![],
        }
    };
    let packet_rsp = make_modbus_rsp_packet(rsp_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.init("./tests/ics_rules_modbus.json"));

    assert_eq!(modbus_rule.detect(&packet_rsp), DetectResult::Hit(RuleAction::Drop));
    assert_eq!(modbus_rule.detect(&packet_req), DetectResult::Hit(RuleAction::Drop));
}

#[test]
fn detect_modbus_read_coils() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 2,
        data: parsing_parser::parsers::modbus_req::Data::ReadCoils {
            start_address: 1,
            count: 1
        }
    };
    let packet_req = make_modbus_req_packet(req_pdu);
    
    let rsp_pdu = parsing_parser::parsers::modbus_rsp::PDU {
        function_code: 2,
        data: parsing_parser::parsers::modbus_rsp::Data::ReadCoils {
            byte_count: 1,
            coil_status: vec![],
        }
    };
    let packet_rsp = make_modbus_rsp_packet(rsp_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.init("./tests/ics_rules_modbus.json"));

    assert_eq!(modbus_rule.detect(&packet_rsp), DetectResult::Hit(RuleAction::Drop));
    assert_eq!(modbus_rule.detect(&packet_req), DetectResult::Hit(RuleAction::Drop));
}

#[test]
fn detect_modbus_read_holding_registers() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 3,
        data: parsing_parser::parsers::modbus_req::Data::ReadHoldingRegisters {
            start_address: 1,
            count: 1
        }
    };
    let packet_req = make_modbus_req_packet(req_pdu);
    
    let rsp_pdu = parsing_parser::parsers::modbus_rsp::PDU {
        function_code: 3,
        data: parsing_parser::parsers::modbus_rsp::Data::ReadHoldingRegisters {
            byte_count: 1,
            coil_status: vec![],
        }
    };
    let packet_rsp = make_modbus_rsp_packet(rsp_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.init("./tests/ics_rules_modbus.json"));

    assert_eq!(modbus_rule.detect(&packet_rsp), DetectResult::Hit(RuleAction::Drop));
    assert_eq!(modbus_rule.detect(&packet_req), DetectResult::Hit(RuleAction::Drop));
}

#[test]
fn detect_modbus_read_input_registers() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 4,
        data: parsing_parser::parsers::modbus_req::Data::ReadInputRegisters {
            start_address: 1,
            count: 1
        }
    };
    let packet_req = make_modbus_req_packet(req_pdu);
    
    let rsp_pdu = parsing_parser::parsers::modbus_rsp::PDU {
        function_code: 4,
        data: parsing_parser::parsers::modbus_rsp::Data::ReadInputRegisters {
            byte_count: 1,
            coil_status: vec![],
        }
    };
    let packet_rsp = make_modbus_rsp_packet(rsp_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.init("./tests/ics_rules_modbus.json"));

    assert_eq!(modbus_rule.detect(&packet_rsp), DetectResult::Hit(RuleAction::Drop));
    assert_eq!(modbus_rule.detect(&packet_req), DetectResult::Hit(RuleAction::Drop));
}

#[test]
fn detect_modbus_write_single_coil() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 5,
        data: parsing_parser::parsers::modbus_req::Data::WriteSingleCoil {
            output_address: 1,
            output_value: 1
        }
    };
    let packet_req = make_modbus_req_packet(req_pdu);
    
    let rsp_pdu = parsing_parser::parsers::modbus_rsp::PDU {
        function_code: 5,
        data: parsing_parser::parsers::modbus_rsp::Data::WriteSingleCoil {
            output_address: 1,
            output_value: 1
        }
    };
    let packet_rsp = make_modbus_rsp_packet(rsp_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.init("./tests/ics_rules_modbus.json"));

    assert_eq!(modbus_rule.detect(&packet_rsp), DetectResult::Hit(RuleAction::Drop));
    assert_eq!(modbus_rule.detect(&packet_req), DetectResult::Hit(RuleAction::Drop));
}

#[test]
fn detect_modbus_write_single_register() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 6,
        data: parsing_parser::parsers::modbus_req::Data::WriteSingleRegister {
            register_address: 1,
            register_value: 1
        }
    };
    let packet_req = make_modbus_req_packet(req_pdu);
    
    let rsp_pdu = parsing_parser::parsers::modbus_rsp::PDU {
        function_code: 6,
        data: parsing_parser::parsers::modbus_rsp::Data::WriteSingleRegister {
            register_address: 1,
            register_value: 1
        }
    };
    let packet_rsp = make_modbus_rsp_packet(rsp_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.init("./tests/ics_rules_modbus.json"));

    assert_eq!(modbus_rule.detect(&packet_rsp), DetectResult::Hit(RuleAction::Drop));
    assert_eq!(modbus_rule.detect(&packet_req), DetectResult::Hit(RuleAction::Drop));
}

#[test]
fn detect_modbus_read_exception_status() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 7,
        data: parsing_parser::parsers::modbus_req::Data::ReadExceptionStatus {}
    };
    let packet_req = make_modbus_req_packet(req_pdu);
    
    let rsp_pdu = parsing_parser::parsers::modbus_rsp::PDU {
        function_code: 7,
        data: parsing_parser::parsers::modbus_rsp::Data::ReadExceptionStatus {
            output_data: 1
        }
    };
    let packet_rsp = make_modbus_rsp_packet(rsp_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.init("./tests/ics_rules_modbus.json"));

    assert_eq!(modbus_rule.detect(&packet_rsp), DetectResult::Hit(RuleAction::Drop));
    assert_eq!(modbus_rule.detect(&packet_req), DetectResult::Hit(RuleAction::Drop));
}

#[test]
fn detect_modbus_get_comm_event_counter() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 11,
        data: parsing_parser::parsers::modbus_req::Data::GetCommEventCounter {}
    };
    let packet_req = make_modbus_req_packet(req_pdu);
    
    let rsp_pdu = parsing_parser::parsers::modbus_rsp::PDU {
        function_code: 11,
        data: parsing_parser::parsers::modbus_rsp::Data::GetCommEventCounter {
            status: 1,
            event_count: 1
        }
    };
    let packet_rsp = make_modbus_rsp_packet(rsp_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.init("./tests/ics_rules_modbus.json"));

    assert_eq!(modbus_rule.detect(&packet_rsp), DetectResult::Hit(RuleAction::Drop));
    assert_eq!(modbus_rule.detect(&packet_req), DetectResult::Hit(RuleAction::Drop));
}

#[test]
fn detect_modbus_get_comm_event_log() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 12,
        data: parsing_parser::parsers::modbus_req::Data::GetCommEventLog {}
    };
    let packet_req = make_modbus_req_packet(req_pdu);
    
    let rsp_pdu = parsing_parser::parsers::modbus_rsp::PDU {
        function_code: 12,
        data: parsing_parser::parsers::modbus_rsp::Data::GetCommEventLog {
            byte_count: 1,
            status: 1,
            event_count: 1,
            message_count: 1,
            events: vec![]
        }
    };
    let packet_rsp = make_modbus_rsp_packet(rsp_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.init("./tests/ics_rules_modbus.json"));

    assert_eq!(modbus_rule.detect(&packet_rsp), DetectResult::Hit(RuleAction::Drop));
    assert_eq!(modbus_rule.detect(&packet_req), DetectResult::Hit(RuleAction::Drop));
}

#[test]
fn detect_modbus_write_multiple_coils() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 15,
        data: parsing_parser::parsers::modbus_req::Data::WriteMultipleCoils {
            start_address: 1,
            output_count: 1,
            byte_count: 1,
            output_values: vec![]
        }
    };
    let packet_req = make_modbus_req_packet(req_pdu);
    
    let rsp_pdu = parsing_parser::parsers::modbus_rsp::PDU {
        function_code: 15,
        data: parsing_parser::parsers::modbus_rsp::Data::WriteMultipleCoils {
            start_address: 1,
            output_count: 1
        }
    };
    let packet_rsp = make_modbus_rsp_packet(rsp_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.init("./tests/ics_rules_modbus.json"));

    assert_eq!(modbus_rule.detect(&packet_rsp), DetectResult::Hit(RuleAction::Drop));
    assert_eq!(modbus_rule.detect(&packet_req), DetectResult::Hit(RuleAction::Drop));
}

#[test]
fn detect_modbus_write_multiple_registers() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 16,
        data: parsing_parser::parsers::modbus_req::Data::WriteMultipleRegisters {
            start_address: 1,
            output_count: 1,
            byte_count: 1,
            output_values: vec![]
        }
    };
    let packet_req = make_modbus_req_packet(req_pdu);
    
    let rsp_pdu = parsing_parser::parsers::modbus_rsp::PDU {
        function_code: 16,
        data: parsing_parser::parsers::modbus_rsp::Data::WriteMultipleRegisters {
            start_address: 1,
            output_count: 1
        }
    };
    let packet_rsp = make_modbus_rsp_packet(rsp_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.init("./tests/ics_rules_modbus.json"));

    assert_eq!(modbus_rule.detect(&packet_rsp), DetectResult::Hit(RuleAction::Drop));
    assert_eq!(modbus_rule.detect(&packet_req), DetectResult::Hit(RuleAction::Drop));
}

#[test]
fn detect_modbus_report_server_id() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 17,
        data: parsing_parser::parsers::modbus_req::Data::ReportServerID {}
    };
    let packet_req = make_modbus_req_packet(req_pdu);
    
    let rsp_pdu = parsing_parser::parsers::modbus_rsp::PDU {
        function_code: 17,
        data: parsing_parser::parsers::modbus_rsp::Data::ReportServerID {
            byte_count: 1,
            server_data: &[]
        }
    };
    let packet_rsp = make_modbus_rsp_packet(rsp_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.init("./tests/ics_rules_modbus.json"));

    assert_eq!(modbus_rule.detect(&packet_rsp), DetectResult::Hit(RuleAction::Drop));
    assert_eq!(modbus_rule.detect(&packet_req), DetectResult::Hit(RuleAction::Drop));
}

#[test]
fn detect_modbus_read_file_record() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 20,
        data: parsing_parser::parsers::modbus_req::Data::ReadFileRecord {
            byte_count: 1,
            sub_requests: vec![]
        }
    };
    let packet_req = make_modbus_req_packet(req_pdu);
    
    let rsp_pdu = parsing_parser::parsers::modbus_rsp::PDU {
        function_code: 20,
        data: parsing_parser::parsers::modbus_rsp::Data::ReadFileRecord {
            byte_count: 1,
            sub_requests: vec![]
        }
    };
    let packet_rsp = make_modbus_rsp_packet(rsp_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.init("./tests/ics_rules_modbus.json"));

    assert_eq!(modbus_rule.detect(&packet_rsp), DetectResult::Hit(RuleAction::Drop));
    assert_eq!(modbus_rule.detect(&packet_req), DetectResult::Hit(RuleAction::Drop));
}

#[test]
fn detect_modbus_write_file_record() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 21,
        data: parsing_parser::parsers::modbus_req::Data::WriteFileRecord {
            byte_count: 1,
            sub_requests: vec![]
        }
    };
    let packet_req = make_modbus_req_packet(req_pdu);
    
    let rsp_pdu = parsing_parser::parsers::modbus_rsp::PDU {
        function_code: 21,
        data: parsing_parser::parsers::modbus_rsp::Data::WriteFileRecord {
            byte_count: 1,
            sub_requests: vec![]
        }
    };
    let packet_rsp = make_modbus_rsp_packet(rsp_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.init("./tests/ics_rules_modbus.json"));

    assert_eq!(modbus_rule.detect(&packet_rsp), DetectResult::Hit(RuleAction::Drop));
    assert_eq!(modbus_rule.detect(&packet_req), DetectResult::Hit(RuleAction::Drop));
}

#[test]
fn detect_modbus_mask_wirte_register() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 22,
        data: parsing_parser::parsers::modbus_req::Data::MaskWriteRegister {
            ref_address: 1,
            and_mask: 1,
            or_mask: 1
        }
    };
    let packet_req = make_modbus_req_packet(req_pdu);
    
    let rsp_pdu = parsing_parser::parsers::modbus_rsp::PDU {
        function_code: 22,
        data: parsing_parser::parsers::modbus_rsp::Data::MaskWriteRegister {
            ref_address: 1,
            and_mask: 1,
            or_mask: 1
        }
    };
    let packet_rsp = make_modbus_rsp_packet(rsp_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.init("./tests/ics_rules_modbus.json"));

    assert_eq!(modbus_rule.detect(&packet_rsp), DetectResult::Hit(RuleAction::Drop));
    assert_eq!(modbus_rule.detect(&packet_req), DetectResult::Hit(RuleAction::Drop));
}

#[test]
fn detect_modbus_read_wirte_multiple_registers() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 23,
        data: parsing_parser::parsers::modbus_req::Data::ReadWriteMultipleRegisters {
            read_start_address: 1,
            read_count: 1,
            write_start_address: 1,
            write_count: 1,
            write_byte_count: 1,
            write_register_values: &[]
        }
    };
    let packet_req = make_modbus_req_packet(req_pdu);
    
    let rsp_pdu = parsing_parser::parsers::modbus_rsp::PDU {
        function_code: 23,
        data: parsing_parser::parsers::modbus_rsp::Data::ReadWriteMultipleRegisters {
            byte_count: 1,
            read_registers_value: &[]
        }
    };
    let packet_rsp = make_modbus_rsp_packet(rsp_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.init("./tests/ics_rules_modbus.json"));

    assert_eq!(modbus_rule.detect(&packet_rsp), DetectResult::Hit(RuleAction::Drop));
    assert_eq!(modbus_rule.detect(&packet_req), DetectResult::Hit(RuleAction::Drop));
}

#[test]
fn detect_modbus_read_fifo_queue() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 24,
        data: parsing_parser::parsers::modbus_req::Data::ReadFIFOQueue {
            fifo_pointer_address: 1
        }
    };
    let packet_req = make_modbus_req_packet(req_pdu);
    
    let rsp_pdu = parsing_parser::parsers::modbus_rsp::PDU {
        function_code: 24,
        data: parsing_parser::parsers::modbus_rsp::Data::ReadFIFOQueue {
            byte_count: 1,
            fifo_count: 1,
            fifo_value_register: &[]
        }
    };
    let packet_rsp = make_modbus_rsp_packet(rsp_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.init("./tests/ics_rules_modbus.json"));

    assert_eq!(modbus_rule.detect(&packet_rsp), DetectResult::Hit(RuleAction::Drop));
    assert_eq!(modbus_rule.detect(&packet_req), DetectResult::Hit(RuleAction::Drop));
}

#[test]
fn detect_modbus_read_coil_exc() {    
    let rsp_pdu = parsing_parser::parsers::modbus_rsp::PDU {
        function_code: 24,
        data: parsing_parser::parsers::modbus_rsp::Data::ReadCoilsExc {
            exception_code: 1
        }
    };
    let packet_rsp = make_modbus_rsp_packet(rsp_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.init("./tests/ics_rules_modbus.json"));

    assert_eq!(modbus_rule.detect(&packet_rsp), DetectResult::Hit(RuleAction::Drop));
}
