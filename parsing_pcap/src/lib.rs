use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError};

use std::fs::File;

use protocols::PacketTrait;

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
                        use protocols::parsers::ethernet::EthernetPacket;
                        // use protocols::parsers_ts::ethernet::EthernetPacket;
                        // use linktype to parse b.data()
                        // println!("{:?}", _b);
                        // println!("{:?}", _b.data);
                        // let packet = parse_packet(&_b.data);
                        match EthernetPacket::parse(&_b.data) {
                            Ok((_input, packet)) => {
                                println!("packet: {:?}", packet);
                            }
                            Err(e) => {
                                println!("parse error: {:?}", e);
                            }
                        }
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

// pub fn parse_pcap_ts(path: &str) {
//     let file = File::open(path).unwrap();
//     let mut num_blocks = 0;
//     let mut reader = LegacyPcapReader::new(65536, file).unwrap();
//     loop {
//         match reader.next() {
//             Ok((offset, block)) => {
//                 println!("[-] Block No.{}", num_blocks);
//                 num_blocks += 1;
//                 match block {
//                     PcapBlockOwned::LegacyHeader(_hdr) => {
//                         println!("{:?}", _hdr);
//                         // save hdr.network (linktype)
//                     }
//                     PcapBlockOwned::Legacy(_b) => {
//                         // use protocols::parsers::ethernet::EthernetPacket;
//                         use protocols::parsers_ts::ethernet::EthernetPacket;
//                         // use linktype to parse b.data()
//                         // println!("{:?}", _b);
//                         // println!("{:?}", _b.data);
//                         // let packet = parse_packet(&_b.data);
//                         match EthernetPacket::parse(&_b.data) {
//                             Ok((_input, packet)) => {
//                                 println!("packet: {:?}", packet);
//                             }
//                             Err(e) => {
//                                 println!("parse error: {:?}", e);
//                             }
//                         }
//                     }
//                     PcapBlockOwned::NG(_) => unreachable!(),
//                 }
//                 reader.consume(offset);
//             }
//             Err(PcapError::Eof) => break,
//             Err(PcapError::Incomplete) => {
//                 reader.refill().unwrap();
//             }
//             Err(e) => panic!("error while reading: {:?}", e),
//         }
//     }
//     println!("[-] number of blocks: {:?}\n", num_blocks);
// }