use super::super::{ipv4, ipv6};

#[derive(Debug, PartialEq)]
pub enum Error {
    Ipv4,
    Ipv6,
}

#[derive(Debug, PartialEq)]
pub enum L2Payload<'a> {
    Ipv4(ipv4::Packet<'a>),
    Ipv6(ipv6::Packet<'a>),
    Unknown(&'a [u8]),
    Error(Error),
}
