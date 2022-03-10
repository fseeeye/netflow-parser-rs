use colored::*;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError};
use walkdir::{DirEntry, WalkDir};

use std::ffi::OsStr;
use std::fs::metadata;
use std::fs::File;
use std::path::Path;

use parsing_rs::prelude::*;
use parsing_suricata::{Surules, VecSurules};

#[test]
fn detect_pcap() {
    // init tracing subscriber
    tracing_subscriber::fmt::init();
    // change paths by yourself.
    let paths = [
        // "../pcap/ICS/opcua/test/opcua_hello.pcap",
        "./tests/detect.pcap",
    ];

    for path in paths.iter() {
        let path_metadata = metadata(path).unwrap();

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
                let file_path = entry.path().to_str().unwrap();
                if let Some("pcap") = Path::new(file_path).extension().and_then(OsStr::to_str) {
                    println!(
                        "[*] Parsing Sub File: {} of {}",
                        file_path.color("cyan"),
                        path.color("cyan")
                    );
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
    let icsrule_path = "./tests/ics_rules.json";
    let mut icsrules = HmIcsRules::new();
    assert_eq!(icsrules.load_rules(icsrule_path), true);
    // 初始化 Suricata 规则
    let surule_path = "./tests/suricata.rules";
    let surules = VecSurules::parse_from_file(surule_path).unwrap();

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
                        // 匹配 ICS 规则
                        // assert_eq!(icsrules.detect(&packet), DetectResult::Hit(RuleAction::Drop));
                        // 匹配 Suricata 规则
                        if let DetectResult::Hit(_id, action) = surules.detect(&packet) {
                            assert_eq!(action, RuleAction::Alert);
                        } else {
                            assert!(false);
                        }
                    }
                    _ => {}
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
