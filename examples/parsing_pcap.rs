use colored::*;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError};
use walkdir::{DirEntry, WalkDir};
use tracing::info;

use std::ffi::OsStr;
use std::fs::metadata;
use std::fs::File;
use std::path::Path;
use std::process;
use std::time::Instant;

use parsing_rs::prelude::*;
use parsing_suricata::{VecSurules, Surules};

fn main() {
    // init tracing subscriber
    tracing_subscriber::fmt::init();
    // change paths by yourself.
    let paths = [
        // OPC UA
        "../pcap/ICS/opcua/test/opcua_hello.pcap",
        // "../pcap/ICS/opcua/test/opcua_ack.pcap",
        // "../pcap/ICS/opcua/test/opcua_error.pcap",
        // "../pcap/ICS/opcua/test/opcua_msg.pcap",
        // IEC104
        // "../pcap/ICS/iec104/test/iec104_i.pcap",
        // Dnp3
        // "../pcap/ICS/dnp3/test/dnp3_simple.pcap",
        // BACnet
        // "../pcap/ICS/bacnet/test/bacnet_ipv4_udp.pcap",
        // S7comm
        // "../pcap/ICS/s7/test/setup_comm.pcap",
        // "../pcap/ICS/s7/test/plc_stop.pcap",
        // "../pcap/ICS/s7/test/pi_service.pcap",
        // "../pcap/ICS/s7/test/read_var.pcap",
        // "../pcap/ICS/s7/test/write_var.pcap",
        // "../pcap/ICS/s7/test/download.pcap",
        // "../pcap/ICS/s7/test/upload.pcap",
        // "../pcap/ICS/s7/test/read_szl.pcap"
        // Mms
        // "../pcap/ICS/iec61850/mms/mms_3.pcap",
        // Ipv4 Option
        // "../pcap/ip/ipv4-options.pcap",
        // Modbus
        // "../pcap/ICS/modbus/test/mod_2.pcap",
        // "./benches/modbus_fins_test.pcap",
    ];

    for path in paths.iter() {
        let path_metadata = match metadata(path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!(
                    "[!] Metadata analysis Error: {}",
                    e.to_string().color("red")
                );
                process::exit(1);
            }
        };

        if path_metadata.is_file() {
            // 解析单个pcap文件
            println!("[*] Parsing File: {}", path.color("cyan"));
            parse_pcap(path)
        } else if path_metadata.is_dir() {
            // 解析文件夹下所有pcap文件
            println!("[*] Parsing Dir: {}", path.color("cyan"));
            let files: Vec<DirEntry> = WalkDir::new(path)
                .into_iter()
                .filter_map(|e| e.ok())
                .collect();
            for entry in files {
                let file_path = entry.path().to_str().unwrap(); // Warning: unhandle error.
                                                                // ref: https://stackoverflow.com/questions/45291832/extracting-a-file-extension-from-a-given-path-in-rust-idiomatically
                if let Some("pcap") = Path::new(file_path).extension().and_then(OsStr::to_str) {
                    println!(
                        "[*] Parsing Sub File: {} of {}",
                        file_path.color("cyan"),
                        path.color("cyan")
                    );
                    // if args.ts == true { parse_pcap_ts(file_path) }
                    parse_pcap(file_path)
                }
            }
        }
    }
}

fn parse_pcap(path: &str) {
    let file = File::open(path).unwrap();
    let mut num_blocks = 0;
    let mut reader = LegacyPcapReader::new(65536, file).unwrap();

    // 初始化 ICS 规则
    let icsrule_path = "./examples/ics_rules.json";
    let mut icsrules = HmIcsRules::new();
    assert_eq!(icsrules.init(icsrule_path), true);
    // 初始化 Suricata 规则
    let surule_path = "./examples/suricata.rules";
    let surules = VecSurules::parse_from_file(surule_path).unwrap();

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                println!("[-] Block No.{}", num_blocks);
                num_blocks += 1;
                match block {
                    PcapBlockOwned::LegacyHeader(_hdr) => {
                        println!("{:?}", _hdr);
                        // save hdr.network (linktype)
                    }
                    PcapBlockOwned::Legacy(_b) => {
                        // use linktype to parse b.data()
                        //debug!("{:?}", _b);
                        //debug!("{:?}", _b.data);
                        let runtimer = Instant::now(); // 程序运行计时变量
                        // 解析数据包
                        let packet = QuinPacket::parse_from_stream(&_b.data, &QuinPacketOptions::default());
                        // 匹配 ICS 规则
                        let ics_rst = icsrules.detect(&packet);
                        // 匹配 Suricata 规则
                        let suricata_rst = surules.detect(&packet);
                        // 完成计时
                        let time = runtimer.elapsed().as_secs_f64();
                        // 打印结果
                        print_parsing_rst(&packet, &ics_rst, &suricata_rst, time);
                    }
                    PcapBlockOwned::NG(_) => unreachable!(),
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
}

fn print_parsing_rst(packet: &QuinPacket, ics_rst: &DetectResult, suricata_rst: &DetectResult, time: f64) {
    match packet {
        QuinPacket::L1(l1) => {
            println!("l1 packet: {:?}", l1);
        }
        QuinPacket::L2(l2) => {
            println!("l2 packet: {:?}", l2);
            println!("l2 dst mac: {:?}", l2.get_dst_mac());
            println!("l2 src mac: {:?}", l2.get_src_mac());
        }
        QuinPacket::L3(l3) => {
            println!("l3 packet: {:?}", l3);
            println!("l3 dst ip: {:?}", l3.get_dst_ip());
            println!("l3 src ip: {:?}", l3.get_src_ip());
        }
        QuinPacket::L4(l4) => {
            println!("l4 packet: {:?}", l4);
            println!("l4 dst port: {:?}", l4.get_dst_port());
            println!("l4 src port: {:?}", l4.get_src_port());
            if l4.error.is_none() {
                println!("Error: {}", String::from(format!("{:?}", l4.error)).green());
            } else {
                println!("Error: {}", String::from(format!("{:?}", l4.error)).red());
            }
        }
        QuinPacket::L5(l5) => {
            println!("l5 packet.");
            println!("l5 app_layer:\n{:#?}", l5.application_layer);
            if l5.error.is_none() {
                println!("Error: {}", String::from(format!("{:?}", l5.error)).green());
            } else {
                println!("Error: {}", String::from(format!("{:?}", l5.error)).red());
            }
        }
    };

    println!("  in time: {:?}", time);

    info!(target: "EXAMPLE(parsing_pcap)", "icsrule check result: {:?}", ics_rst);
    info!(target: "EXAMPLE(parsing_pcap)", "suricata check result: {:?}", suricata_rst);
}
