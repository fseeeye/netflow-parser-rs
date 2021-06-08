use nom::bits::bits;
use nom::bits::complete::take as take_bits;
use nom::bytes::complete::{tag, take};
use nom::combinator::eof;
use nom::multi::count;
use nom::number::complete::{be_u16, be_u32, u8};
use nom::sequence::tuple;
use nom::IResult;

use super::payload::L4Payload;

#[derive(Debug, PartialEq)]
pub struct Tcp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub header_length: u8,
    pub reserved: u8,
    pub flags: u16,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: Option<&'a [u8]>,
}

pub fn parse_tcp(input: &[u8]) -> IResult<&[u8], Tcp> {
    let (input, src_port) = be_u16(input)?;
    let (input, dst_port) = be_u16(input)?;
    let (input, seq) = be_u32(input)?;
    let (input, ack) = be_u32(input)?;
    let (input, (header_length, reserved, flags)) =
        bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
            take_bits(4usize),
            take_bits(3usize),
            take_bits(9usize),
        )))(input)?;
    let (input, window_size) = be_u16(input)?;
    let (input, checksum) = be_u16(input)?;
    let (input, urgent_pointer) = be_u16(input)?;
    let (input, options) = if (header_length * 4) > 20 {
        let (input, options) = take(header_length * 4 - 20)(input)?;
        Ok((input, Some(options)))
    } else {
        Ok((input, None))
    }?;
    Ok((
        input,
        Tcp {
            src_port,
            dst_port,
            seq,
            ack,
            header_length,
            reserved,
            flags,
            window_size,
            checksum,
            urgent_pointer,
            options,
        },
    ))
}

// #[derive(Debug, PartialEq)]
// pub struct Tcp<'a> {
//     pub src_port: u16,
//     pub dst_port: u16,
//     pub seq: u32,
//     pub ack: u32,
//     pub header_length: u8,
//     pub reserved: u8,
//     pub flags: u16,
//     pub window_size: u16,
//     pub checksum: u16,
//     pub urgent_pointer: u16,
//     pub options: Option<&'a [u8]>,
// }

// // #[derive(Debug, PartialEq)]
// // pub struct Tcp<'a> {
// //     pub header: TcpHeader,
// //     pub options: Option<&'a [u8]>,
// // }

// fn parse_tcp(input: &[u8]) -> IResult<&[u8], Tcp> {
//     let (input, src_port) = be_u16(input)?;
//     let (input, dst_port) = be_u16(input)?;
//     let (input, seq) = be_u32(input)?;
//     let (input, ack) = be_u32(input)?;
//     let (input, (header_length, reserved, flags)) =
//         bits::<_, _, nom::error::Error<(&[u8], usize)>, _, _>(tuple((
//             take_bits(4usize),
//             take_bits(3usize),
//             take_bits(9usize),
//         )))(input)?;
//     let (input, window_size) = be_u16(input)?;
//     let (input, checksum) = be_u16(input)?;
//     let (input, urgent_pointer) = be_u16(input)?;
//     let (input, options) = if (header_length * 4) > 20 {
//         let (input, options) = take(header_length * 4 - 20)(input)?;
//         Ok((input, Some(options)))
//     } else {
//         Ok((input, None))
//     }?;

//     // let (input, src_port) = take_bits(16usize)(input)?;
//     // let (input, dst_port) = take_bits(16usize)(input)?;
//     // let (input, seq) = take_bits(32usize)(input)?;
//     // let (input, ack) = take_bits(32usize)(input)?;
//     // let (input, header_length) = take_bits(4usize)(input)?;
//     // let (input, reserved) = take_bits(3usize)(input)?;
//     // let (input, flags) = take_bits(9usize)(input)?;
//     // let (input, window_size) = take_bits(16usize)(input)?;
//     // let (input, checksum) = take_bits(16usize)(input)?;
//     // let (input, urgent_pointer) = take_bits(16usize)(input)?;
//     Ok((
//         input,
//         Tcp {
//             src_port,
//             dst_port,
//             seq,
//             ack,
//             header_length,
//             reserved,
//             flags,
//             window_size,
//             checksum,
//             urgent_pointer,
//             options,
//         },
//     ))
// }

#[derive(Debug, PartialEq)]
pub struct Packet<'a> {
    header: Tcp<'a>,
    payload: L4Payload<'a>,
}

fn parse_tcp_payload<'a>(input: &'a [u8], header: &Tcp) -> (&'a [u8], L4Payload<'a>) {
    use super::modbus::parse_modbus_packet;
    use super::payload::l4;
    if header.src_port == 502 || header.dst_port == 502 {
        return match parse_modbus_packet(input) {
            Ok((input, modbus)) => (input, L4Payload::Modbus(modbus)),
            Err(_) => (input, L4Payload::Error(l4::Error::Modbus)),
        };
    }
    (input, L4Payload::Unknown(input))
}

pub fn parse_tcp_packet<'a>(input: &'a [u8]) -> nom::IResult<&'a [u8], Packet<'a>> {
    let (input, header) = parse_tcp(input)?;
    let (input, payload) = parse_tcp_payload(input, &header);
    let packet = Packet { header, payload };
    Ok((input, packet))
}
