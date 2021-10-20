use colored::*;
use parsing_rs::{QuinPacket, Rules, detect_ics};
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError};
use walkdir::{DirEntry, WalkDir};

use std::ffi::OsStr;
use std::fs::metadata;
use std::fs::File;
use std::path::Path;
use std::process;
use std::time::Instant;

fn main() {
    // change paths by yourself.
    let paths = [
        // Dnp3
        "../pcap/ICS/dnp3/test/dnp3_simple.pcap",
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

    let rule_path = "./examples/ics_rules.json";
    let mut rules = Rules::new();
    assert_eq!(rules.init(rule_path), true);

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
                        // println!("{:?}", _b);
                        // println!("{:?}", _b.data);
                        // let packet = parse_packet(&_b.data);
                        let packet = parse_ethernet_quin_packet(&_b.data);
                        let res = detect_ics(&rules, &packet);
                        println!("rule check: {:?}", res);
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
    println!("[-] number of blocks: {:?}\n", num_blocks);
}

fn parse_ethernet_quin_packet(input: &[u8]) -> QuinPacket {
    use parsing_rs::*;

    println!("{:?}", &input);
    let runtimer = Instant::now(); // 程序运行计时变量
    let packet = parse_quin_packet(input, &QuinPacketOptions::default());
    match &packet {
        QuinPacket::L1(l1) => {
            let time = runtimer.elapsed().as_secs_f64();
            println!("l1 packet: {:?}", l1);
            println!("  in time: {:?}", time);
        }
        QuinPacket::L2(l2) => {
            let time = runtimer.elapsed().as_secs_f64();
            println!("l2 packet: {:?}", l2);
            println!("l2 dst mac: {:?}", l2.get_dst_mac());
            println!("l2 src mac: {:?}", l2.get_src_mac());
            println!("  in time: {:?}", time);
        }
        QuinPacket::L3(l3) => {
            let time = runtimer.elapsed().as_secs_f64();
            println!("l3 packet: {:?}", l3);
            println!("l3 dst ip: {:?}", l3.get_dst_ip());
            println!("l3 src ip: {:?}", l3.get_src_ip());
            println!("  in time: {:?}", time);
        }
        QuinPacket::L4(l4) => {
            let time = runtimer.elapsed().as_secs_f64();
            println!("l4 packet: {:?}", l4);
            println!("l4 dst port: {:?}", l4.get_dst_port());
            println!("l4 src port: {:?}", l4.get_src_port());
            if l4.error.is_none() {
                println!("Error: {}", String::from(format!("{:?}", l4.error)).green());
            } else {
                println!("Error: {}", String::from(format!("{:?}", l4.error)).red());
            }
            println!("  in time: {:?}", time);
        }
        QuinPacket::L5(l5) => {
            let time = runtimer.elapsed().as_secs_f64();
            println!("l5 packet.");
            println!("l5 app_layer:\n{:#?}", l5.application_layer);
            if l5.error.is_none() {
                println!("Error: {}", String::from(format!("{:?}", l5.error)).green());
            } else {
                println!("Error: {}", String::from(format!("{:?}", l5.error)).red());
            }
            println!("  in time: {:?}", time);
        }
    };

    packet
}
