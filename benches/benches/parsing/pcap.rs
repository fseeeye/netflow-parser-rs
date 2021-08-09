use criterion::{Criterion, black_box, criterion_group, criterion_main};

use std::fs::File;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{LegacyPcapReader, PcapBlockOwned, PcapError};
use parsing_rs::{QuinPacket, QuinPacketOptions, parse_quin_packet};

fn quin_parsing_benchmark_pcap(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("quin_parsing_benchmark");
    group.warm_up_time(std::time::Duration::from_millis(500));
    group.measurement_time(std::time::Duration::from_secs(10));

    let path = "./modbus_fins_test.pcap"; // change by yourself
    
    group.bench_function("parse_pcap 1000", |bencher| bencher.iter(|| {
        let file = File::open(black_box(path)).unwrap();

        let mut reader = LegacyPcapReader::new(65536, file).unwrap();
        loop {
            match reader.next() {
                Ok((offset, block)) => {
                    match block {
                        PcapBlockOwned::LegacyHeader(_hdr) => {}
                        PcapBlockOwned::Legacy(_b) => {
                            match parse_quin_packet(black_box(&_b.data), black_box(QuinPacketOptions::default())) {
                                QuinPacket::L1(_l1) => {}
                                QuinPacket::L2(_l2) => {
                                    // l2.get_dst_mac();
                                }
                                QuinPacket::L3(_l3) => {
                                    // l3.get_dst_mac();
                                }
                                QuinPacket::L4(_l4) => {
                                    // l4.get_dst_mac();
                                }
                                QuinPacket::L5(_l5) => {
                                    // l5.get_dst_mac();
                                }
                            };
                        }
                        PcapBlockOwned::NG(_) => unreachable!(),
                    }
                    reader.consume(offset);
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete) => {
                    reader.refill().unwrap();
                }
                Err(e) => {
                    print!("Error!");
                    panic!("error while reading: {:?}", e)
                },
            }
        }
    }));

    group.finish();
}

fn quin_parsing_benchmark_modbus(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("quin_parsing_benchmark");
    group.warm_up_time(std::time::Duration::from_millis(500));
    group.measurement_time(std::time::Duration::from_secs(10));
    group.sample_size(1000);

    let input = [0, 14, 198, 208, 125, 185, 76, 237, 251, 115, 84, 107, 8, 0, 69, 0, 0, 52, 123, 78, 64, 0, 128, 6, 0, 0, 192, 168, 3, 190, 192, 168, 3, 189, 208, 8, 1, 246, 235, 71, 73, 93, 70, 24, 37, 8, 80, 24, 2, 12, 136, 242, 0, 0, 1, 0, 0, 0, 0, 6, 1, 2, 0, 0, 0, 4];
    let options = QuinPacketOptions::default();

    group.bench_function("parse_modbus 1 (Request)(func_code: 2)", |bencher| bencher.iter(|| parse_quin_packet(black_box(&input), black_box(options))));

    group.finish();
}

fn quin_parsing_benchmark_tcp(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("quin_parsing_benchmark");
    group.warm_up_time(std::time::Duration::from_millis(500));
    group.measurement_time(std::time::Duration::from_secs(10));
    group.sample_size(1000);

    let input = [0, 14, 198, 208, 125, 185, 76, 237, 251, 115, 84, 107, 8, 0, 69, 0, 0, 40, 122, 181, 64, 0, 128, 6, 0, 0, 192, 168, 3, 190, 192, 168, 3, 189, 206, 189, 1, 246, 236, 200, 118, 229, 57, 109, 163, 54, 80, 16, 2, 12, 136, 230, 0, 0];
    let options = QuinPacketOptions::default();

    group.bench_function("parse_tcp 1", |bencher| bencher.iter(|| parse_quin_packet(black_box(&input), black_box(options))));
    
    group.finish();
}

fn quin_parsing_benchmark_udp(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("quin_parsing_benchmark");
    group.warm_up_time(std::time::Duration::from_millis(500));
    group.measurement_time(std::time::Duration::from_secs(10));
    group.sample_size(1000);

    let input = [0, 208, 3, 179, 167, 252, 0, 19, 114, 151, 162, 212, 8, 0, 69, 0, 0, 42, 130, 199, 64, 0, 64, 17, 18, 142, 10, 4, 14, 102, 10, 130, 130, 130, 229, 98, 37, 128, 0, 22, 101, 242];
    let options = QuinPacketOptions::default();

    group.bench_function("parse_udp 1", |bencher| bencher.iter(|| parse_quin_packet(black_box(&input), black_box(options))));

    group.finish();
}

criterion_group!(benches, quin_parsing_benchmark_pcap, quin_parsing_benchmark_modbus, quin_parsing_benchmark_tcp, quin_parsing_benchmark_udp);
criterion_main!(benches);