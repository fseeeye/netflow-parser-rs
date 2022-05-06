use std::{net::Ipv4Addr, str::FromStr};

use parsing_icsrule::HmIcsRules;
use parsing_parser::{
    parsers::{EthernetHeader, Ipv4Header, ModbusReqHeader, TcpHeader},
    ApplicationLayer, L5Packet, LinkLayer, MacAddress, NetworkLayer, QuinPacket, TransportLayer,
};
use parsing_rule::{RuleAction, RulesDetectorICS, DetectResultICS};

fn make_modbus_req_packet(req_pdu: parsing_parser::parsers::modbus_req::PDU) -> QuinPacket {
    let app_layer = ApplicationLayer::ModbusReq(ModbusReqHeader {
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
            options: None,
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
            padding: None,
            payload: &[],
        }),
        application_layer: app_layer,
        remain: &[],
        error: None,
    };

    return QuinPacket::L5(l5);
}

#[test]
fn detect_modbus_read_coils() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 1,
        data: parsing_parser::parsers::modbus_req::Data::ReadCoils {
            start_address: 1,
            count: 1,
        },
    };
    let packet_req = make_modbus_req_packet(req_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.load_rules("./tests/ics_rules_modbus.json"));

    assert_eq!(
        modbus_rule.detect(&packet_req),
        DetectResultICS::Hit(1, RuleAction::Alert)
    );
}

#[test]
fn detect_modbus_read_discrete_inputs() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 2,
        data: parsing_parser::parsers::modbus_req::Data::ReadDiscreteInputs {
            start_address: 1,
            count: 1,
        },
    };
    let packet_req = make_modbus_req_packet(req_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.load_rules("./tests/ics_rules_modbus.json"));

    assert_eq!(
        modbus_rule.detect(&packet_req),
        DetectResultICS::Hit(2, RuleAction::Alert)
    );
}

#[test]
fn detect_modbus_read_holding_registers() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 3,
        data: parsing_parser::parsers::modbus_req::Data::ReadHoldingRegisters {
            start_address: 1,
            count: 1,
        },
    };
    let packet_req = make_modbus_req_packet(req_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.load_rules("./tests/ics_rules_modbus.json"));

    assert_eq!(
        modbus_rule.detect(&packet_req),
        DetectResultICS::Hit(3, RuleAction::Alert)
    );
}

#[test]
fn detect_modbus_read_input_registers() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 4,
        data: parsing_parser::parsers::modbus_req::Data::ReadInputRegisters {
            start_address: 1,
            count: 1,
        },
    };
    let packet_req = make_modbus_req_packet(req_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.load_rules("./tests/ics_rules_modbus.json"));

    assert_eq!(
        modbus_rule.detect(&packet_req),
        DetectResultICS::Hit(4, RuleAction::Alert)
    );
}

#[test]
fn detect_modbus_write_single_coil() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 5,
        data: parsing_parser::parsers::modbus_req::Data::WriteSingleCoil {
            output_address: 1,
            output_value: 255,
        },
    };
    let packet_req = make_modbus_req_packet(req_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.load_rules("./tests/ics_rules_modbus.json"));

    assert_eq!(
        modbus_rule.detect(&packet_req),
        DetectResultICS::Hit(5, RuleAction::Alert)
    );
}

#[test]
fn detect_modbus_write_single_register() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 6,
        data: parsing_parser::parsers::modbus_req::Data::WriteSingleRegister {
            register_address: 1,
            register_value: 257,
        },
    };
    let packet_req = make_modbus_req_packet(req_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.load_rules("./tests/ics_rules_modbus.json"));

    assert_eq!(
        modbus_rule.detect(&packet_req),
        DetectResultICS::Hit(6, RuleAction::Alert)
    );
}

#[test]
fn detect_modbus_read_exception_status() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 7,
        data: parsing_parser::parsers::modbus_req::Data::ReadExceptionStatus {},
    };
    let packet_req = make_modbus_req_packet(req_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.load_rules("./tests/ics_rules_modbus.json"));

    assert_eq!(
        modbus_rule.detect(&packet_req),
        DetectResultICS::Hit(7, RuleAction::Alert)
    );
}

#[test]
fn detect_modbus_get_comm_event_counter() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 11,
        data: parsing_parser::parsers::modbus_req::Data::GetCommEventCounter {},
    };
    let packet_req = make_modbus_req_packet(req_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.load_rules("./tests/ics_rules_modbus.json"));

    assert_eq!(
        modbus_rule.detect(&packet_req),
        DetectResultICS::Hit(11, RuleAction::Alert)
    );
}

#[test]
fn detect_modbus_get_comm_event_log() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 12,
        data: parsing_parser::parsers::modbus_req::Data::GetCommEventLog {},
    };
    let packet_req = make_modbus_req_packet(req_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.load_rules("./tests/ics_rules_modbus.json"));

    assert_eq!(
        modbus_rule.detect(&packet_req),
        DetectResultICS::Hit(12, RuleAction::Alert)
    );
}

#[test]
fn detect_modbus_write_multiple_coils() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 15,
        data: parsing_parser::parsers::modbus_req::Data::WriteMultipleCoils {
            start_address: 1,
            output_count: 1,
            byte_count: 3,
            output_values: vec![1, 2, 3],
        },
    };
    let packet_req = make_modbus_req_packet(req_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.load_rules("./tests/ics_rules_modbus.json"));

    assert_eq!(
        modbus_rule.detect(&packet_req),
        DetectResultICS::Hit(15, RuleAction::Alert)
    );
}

#[test]
fn detect_modbus_write_multiple_registers() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 16,
        data: parsing_parser::parsers::modbus_req::Data::WriteMultipleRegisters {
            start_address: 1,
            output_count: 1,
            byte_count: 3,
            output_values: vec![1, 2, 3],
        },
    };
    let packet_req = make_modbus_req_packet(req_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.load_rules("./tests/ics_rules_modbus.json"));

    assert_eq!(
        modbus_rule.detect(&packet_req),
        DetectResultICS::Hit(16, RuleAction::Alert)
    );
}

#[test]
fn detect_modbus_report_server_id() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 17,
        data: parsing_parser::parsers::modbus_req::Data::ReportServerID {},
    };
    let packet_req = make_modbus_req_packet(req_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.load_rules("./tests/ics_rules_modbus.json"));

    assert_eq!(
        modbus_rule.detect(&packet_req),
        DetectResultICS::Hit(17, RuleAction::Alert)
    );
}

#[test]
fn detect_modbus_read_file_record() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 20,
        data: parsing_parser::parsers::modbus_req::Data::ReadFileRecord {
            byte_count: 1,
            sub_requests: vec![],
        },
    };
    let packet_req = make_modbus_req_packet(req_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.load_rules("./tests/ics_rules_modbus.json"));

    assert_eq!(
        modbus_rule.detect(&packet_req),
        DetectResultICS::Hit(20, RuleAction::Alert)
    );
}

#[test]
fn detect_modbus_write_file_record() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 21,
        data: parsing_parser::parsers::modbus_req::Data::WriteFileRecord {
            byte_count: 1,
            sub_requests: vec![],
        },
    };
    let packet_req = make_modbus_req_packet(req_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.load_rules("./tests/ics_rules_modbus.json"));

    assert_eq!(
        modbus_rule.detect(&packet_req),
        DetectResultICS::Hit(21, RuleAction::Alert)
    );
}

#[test]
fn detect_modbus_mask_wirte_register() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 22,
        data: parsing_parser::parsers::modbus_req::Data::MaskWriteRegister {
            ref_address: 1,
            and_mask: 1,
            or_mask: 2,
        },
    };
    let packet_req = make_modbus_req_packet(req_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.load_rules("./tests/ics_rules_modbus.json"));

    assert_eq!(
        modbus_rule.detect(&packet_req),
        DetectResultICS::Hit(22, RuleAction::Alert)
    );
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
            write_byte_count: 3,
            write_register_values: vec![1, 2, 3],
        },
    };
    let packet_req = make_modbus_req_packet(req_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.load_rules("./tests/ics_rules_modbus.json"));

    assert_eq!(
        modbus_rule.detect(&packet_req),
        DetectResultICS::Hit(23, RuleAction::Alert)
    );
}

#[test]
fn detect_modbus_read_fifo_queue() {
    let req_pdu = parsing_parser::parsers::modbus_req::PDU {
        function_code: 24,
        data: parsing_parser::parsers::modbus_req::Data::ReadFIFOQueue {
            fifo_pointer_address: 1,
        },
    };
    let packet_req = make_modbus_req_packet(req_pdu);

    let mut modbus_rule = HmIcsRules::new();
    assert!(modbus_rule.load_rules("./tests/ics_rules_modbus.json"));

    assert_eq!(
        modbus_rule.detect(&packet_req),
        DetectResultICS::Hit(24, RuleAction::Alert)
    );
}
