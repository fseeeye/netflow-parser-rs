use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError};

use std::fs::File;

use parsing_parser::{QuinPacket, QuinPacketOptions, ParseError};


fn parse_pcap(path: &str)-> Result<(), ()> {
    let file = File::open(path).unwrap();
    let mut num_blocks = 0;
    let mut reader = LegacyPcapReader::new(65536, file).unwrap();

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                println!("[-] Block No.{}", num_blocks);
                num_blocks += 1;
                match block {
                    PcapBlockOwned::Legacy(_b) => {
                        // 解析数据包
                        let packet =
                            QuinPacket::parse_from_stream(&_b.data, &QuinPacketOptions::default());
                        if let Some(err) = packet.get_error() {
                            if err != ParseError::NotEndPayload {
                                println!("[!] Find Error Packet: {:?}", packet);
                                return Err(());
                            }
                        }
                    }
                    _ => {},
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete) => {
                reader.refill().unwrap();
            }
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }
    println!("[-] total blocks: {:?}\n", num_blocks);

    Ok(())
}

#[test]
fn parse_modbus_pcap() {
    let modbus_pcap_path = "./tests/modbus_all.pcap";

    assert!(parse_pcap(modbus_pcap_path).is_ok());
}

#[test]
fn parse_fins_pcap() {
    let fins_pcap_path = "./tests/fins_all.pcap";

    assert!(parse_pcap(fins_pcap_path).is_ok());
}

#[test]
fn parse_s7comm_pcap() {
    let s7comm_pcap_path = "./tests/s7comm_all.pcap";

    assert!(parse_pcap(s7comm_pcap_path).is_ok());
}

#[test]
fn parse_dnp3_pcap() {
    let dnp3_pcap_path = "./tests/dnp3_all.pcap";

    assert!(parse_pcap(dnp3_pcap_path).is_ok());
}

#[test]
fn parse_bacnet_pcap() {
    let bacnet_pcap_path = "./tests/bacnet_simple.pcap";

    assert!(parse_pcap(bacnet_pcap_path).is_ok());
}

#[test]
fn parse_iec104_pcap() {
    let iec104_pcap_path = "./tests/iec104_all.pcap";
    assert!(parse_pcap(iec104_pcap_path).is_ok());
}

#[test]
fn parse_opcua_pcap() {
    tracing_subscriber::fmt::init();
    let opcua_pcap_path = [
        "./tests/opcua_msg.pcap",
        "./tests/opcua_ack.pcap",
        "./tests/opcua_error.pcap",
        "./tests/opcua_hello.pcap",
        "./tests/opcua_all.pcap"
    ];

    for path in opcua_pcap_path {
        assert!(parse_pcap(path).is_ok());
    }
}

#[test]
fn parse_mms_pcap() {
    // tracing_subscriber::fmt::init();
    let mms_pcap_path = "./tests/mms_3.pcap";
    
    assert!(parse_pcap(mms_pcap_path).is_ok());
}
