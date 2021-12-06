use core::slice;

use parsing_parser::{
    ApplicationLayer, LinkLevel, NetLevel, QuinPacket, QuinPacketOptions,
    TransLevel,
};

#[no_mangle]
pub extern "C" fn init_parse_option() -> *const QuinPacketOptions {
    &QuinPacketOptions::default()
}

#[no_mangle]
pub extern "C" fn parse_packet<'a>(
    input_ptr: *const u8,
    input_len: u16,
    option_ptr: *const QuinPacketOptions,
) -> *const QuinPacket<'a> {
    let input = unsafe {
        assert!(!input_ptr.is_null());
        slice::from_raw_parts(input_ptr, input_len.into())
    };

    let option = unsafe {
        assert!(!option_ptr.is_null());
        &*option_ptr
    };

    let packet = QuinPacket::parse_from_stream(input, option);

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
            println!("[-] l1 packet.");
        }
        QuinPacket::L2(l2) => {
            println!("[-] l2 packet.");
            println!("  dst mac: {:?}", l2.get_dst_mac());
            println!("  src mac: {:?}", l2.get_src_mac());
        }
        QuinPacket::L3(l3) => {
            println!("[-] l3 packet.");
            println!("  dst ip: {:?}", l3.get_dst_ip());
            println!("  src ip: {:?}", l3.get_src_ip());
        }
        QuinPacket::L4(l4) => {
            println!("[-] l4 packet.");
            println!("  dst port: {:?}", l4.get_dst_port());
            println!("  src port: {:?}", l4.get_src_port());
            println!("  error: {:?}", l4.error);
        }
        QuinPacket::L5(l5) => {
            println!("[-] l5 packet.");
            // println!("  application layer:\n{:?}", l5.application_layer);
            match &l5.application_layer {
                ApplicationLayer::ModbusReq(req) => {
                    println!(
                        "  application layer: ModbusReq({:?}).",
                        req.pdu.function_code
                    );
                }
                ApplicationLayer::ModbusRsp(rsp) => {
                    println!(
                        "  application layer: ModbusRsp({:?}).",
                        rsp.pdu.function_code
                    );
                }
                _ => println!("  application layer: Other."),
            }
            println!("  error: {:?}", l5.error);
        }
    };
}
