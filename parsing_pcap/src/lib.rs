use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError};

use std::fs::File;
use std::time::Instant;

pub fn parse_pcap(path: &str) {
    let file = File::open(path).unwrap();
    let mut num_blocks = 0;
    let mut reader = LegacyPcapReader::new(65536, file).unwrap();
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
                        parse_ethernet_quin_packet(&_b.data);
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

fn parse_ethernet_quin_packet(input: &[u8]) {
    use protocols::*;

    let runtimer = Instant::now(); // 程序运行计时变量
    match parse_quin_enum_packet(input, QuinPacketOptions::default()) {
        QuinPacket::L1(l1) => {
            let time = runtimer.elapsed().as_secs_f64();
            println!("  in time: {:?}", time);
            println!("l1 packet: {:?}", l1);
        },
        QuinPacket::L2(l2) => {
            let time = runtimer.elapsed().as_secs_f64();
            println!("  in time: {:?}", time);
            println!("l2 packet: {:?}", l2);
        },
        QuinPacket::L3(l3) => {
            let time = runtimer.elapsed().as_secs_f64();
            println!("  in time: {:?}", time);
            println!("l3 packet: {:?}", l3);
        },
        QuinPacket::L4(l4) => {
            let time = runtimer.elapsed().as_secs_f64();
            println!("  in time: {:?}", time);
            println!("l4 packet: {:?}", l4);
        },
        QuinPacket::L5(l5) => {
            let time = runtimer.elapsed().as_secs_f64();
            println!("  in time: {:?}", time);
            println!("l5 packet: {:?}", l5);
        },
    };
}