use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError};

use std::fs::File;

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
                        parse_ethernet_packet(&_b.data);
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

fn parse_ethernet_packet(input: &[u8]) {
    // use protocols::HeaderTrait;
    // use protocols::parsers::ethernet::EthernetHeader;
    // use protocols::parsers_ts::ethernet::EthernetPacket;

    // match EthernetHeader::parse(input) {
    //     Ok((_input, header)) => {
    //         println!("header: {:?}", header);
    //     }
    //     Err(e) => {
    //         println!("parse error: {:?}", e);
    //     }
    // }

    use protocols::*;

    let mut packet = VecPacket::new(input, VecPacketOptions::new());
    let parsers_map = parsers_map_init();

    packet.parse(parsers_map);
    println!("layers: {:?}", packet.get_layers());
    // if let Some(&Layer::Ethernet(eth)) = packet.get_layer(LayerType::Ethernet) {
    //     println!("Eth layer: {:?}", eth);
    //     println!("Eth layer - dst_mac: {:?}", eth.dst_mac);
    //     println!("Eth layer - src_mac: {:?}", eth.src_mac);
    // }
}