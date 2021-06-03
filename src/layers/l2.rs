use crate::error::Error;
use crate::protocols::{ethernet, ethernet::parse_ethernet};

#[derive(Debug, PartialEq)]
pub enum L2<'a> {
    Ethernet(ethernet::Ethernet<'a>),
    Unknown,
    Error(Error),
}

pub fn parse_l2(input: &[u8]) -> (&[u8], L2) {
    let parsed = parse_ethernet(input);
    match parsed {
        Ok((input, ethernet)) => (input, L2::Ethernet(ethernet)),
        Err(_) => (input, L2::Error(Error::Ethernet)),
    }
}
