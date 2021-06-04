mod protocols;

use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError};
use std::fs::File;

fn main() {
    let path = r"C:\Users\slnya\Documents\pcap\ICS\modbus\mod_3.pcap";
    let file = File::open(path).unwrap();
    let mut num_blocks = 0;
    let mut reader = LegacyPcapReader::new(65536, file).unwrap();
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                println!("got new block");
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

                        println!("packet: {:?}", _b.data);
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
    println!("number of blocks: {:?}", num_blocks);
}
