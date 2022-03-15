use core::slice;

use parsing_parser::{
    ApplicationLayer, L1Packet, LinkLevel, NetLevel, ParseError, QuinPacket, QuinPacketOptions,
    TransLevel,
};

/// 初始化数据包解析选项
#[no_mangle]
pub extern "C" fn init_parse_option_rs() -> *mut QuinPacketOptions {
    let parser_options_ptr = Box::into_raw(Box::new(QuinPacketOptions::default()));

    tracing::debug!("Parser Options init Done.");

    parser_options_ptr
}

/// 解析数据包
#[no_mangle]
pub extern "C" fn parse_packet_rs<'a>(
    input_ptr: *const u8,
    input_len: u16,
    option_ptr: *const QuinPacketOptions,
) -> *mut QuinPacket<'a> {
    if input_ptr.is_null() {
        tracing::warn!("Packet parsing: input bytes ptr is null!");
        return Box::into_raw(Box::new(QuinPacket::L1(L1Packet {
            error: Some(ParseError::Adaptor),
            remain: &[],
        })));
    }

    if option_ptr.is_null() {
        tracing::warn!("Packet parsing: option ptr is null!");
        return Box::into_raw(Box::new(QuinPacket::L1(L1Packet {
            error: Some(ParseError::Adaptor),
            remain: &[],
        })));
    }

    let input = unsafe { slice::from_raw_parts(input_ptr, input_len.into()) };

    let option = unsafe { &*option_ptr };

    let packet = Box::into_raw(Box::new(QuinPacket::parse_from_stream(input, option)));

    packet
}

/// 释放数据包解析结果内存
#[no_mangle]
pub extern "C" fn free_packet_rs(packet_ptr: *mut QuinPacket) {
    if packet_ptr.is_null() {
        tracing::warn!("Packet free: packet ptr is null!");
        return;
    }
    unsafe { Box::from_raw(packet_ptr) };

    tracing::trace!("Packet free Done.");
}

/// 展示数据包解析结果
#[no_mangle]
pub extern "C" fn show_packet_rs(packet_ptr: *const QuinPacket) {
    if packet_ptr.is_null() {
        tracing::warn!("Packet parsing: packet ptr is null! return.");
        return;
    }

    let packet = unsafe { &*packet_ptr };

    match packet {
        QuinPacket::L1(_l1) => {
            println!("[-] l1 packet.");
        }
        QuinPacket::L2(l2) => {
            println!("[-] l2 packet.");
            println!("  src mac: {:?}", l2.get_src_mac());
            println!("  dst mac: {:?}", l2.get_dst_mac());
            println!("  error: {:?}", l2.error);
        }
        QuinPacket::L3(l3) => {
            println!("[-] l3 packet.");
            println!("  src ip: {:?}", l3.get_src_ip());
            println!("  dst ip: {:?}", l3.get_dst_ip());
            println!("  error: {:?}", l3.error);
        }
        QuinPacket::L4(l4) => {
            println!("[-] l4 packet.");
            println!("  src port: {:?}", l4.get_src_port());
            println!("  dst port: {:?}", l4.get_dst_port());
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
