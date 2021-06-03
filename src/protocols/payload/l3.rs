use super::super::{tcp, udp};

#[derive(Debug, PartialEq)]
pub enum L3Payload<'a> {
    Tcp(tcp::Packet<'a>),
    Udp(udp::Packet<'a>),
    Unknown(&'a [u8]),
}
