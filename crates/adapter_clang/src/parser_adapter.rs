use core::slice;

use parsing_parser::{
    parse_quin_packet,
    QuinPacket,
    LinkLevel, NetLevel, TransLevel
};

#[no_mangle]
pub extern "C" fn parse_packet<'a>(input_ptr: *const u8, input_len: u16) -> *const QuinPacket<'a> {
    let input = unsafe {
        assert!(!input_ptr.is_null());
        slice::from_raw_parts(input_ptr, input_len.into())
    };
    let option = Default::default();

    let packet = parse_quin_packet(input, &option);
    
    &packet
}

#[no_mangle]
pub extern "C" fn show_packet(packet_ptr: *const QuinPacket) {
    let packet = unsafe {
        assert!(!packet_ptr.is_null());
        &*packet_ptr
    };

    match packet {
        QuinPacket::L1(_l1) => {
            println!("l1 packet.");
        }
        QuinPacket::L2(l2) => {
            println!("l2 packet.");
            println!("l2 dst mac: {:?}", l2.get_dst_mac());
            println!("l2 src mac: {:?}", l2.get_src_mac());
        }
        QuinPacket::L3(l3) => {
            println!("l3 packet.");
            println!("l3 dst ip: {:?}", l3.get_dst_ip());
            println!("l3 src ip: {:?}", l3.get_src_ip());
        }
        QuinPacket::L4(l4) => {
            println!("l4 packet.");
            println!("l4 dst port: {:?}", l4.get_dst_port());
            println!("l4 src port: {:?}", l4.get_src_port());
        }
        QuinPacket::L5(l5) => {
            println!("l5 packet.");
            println!("l5 layer packet: {:?}", l5.application_layer);
        }
    };
}