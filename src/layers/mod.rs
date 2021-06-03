mod l2;
mod l3;

use l2::{parse_l2, L2};
use l3::{parse_l3, L3};

#[derive(Debug, PartialEq)]
pub struct Packet<'a> {
    pub l2: L2<'a>,
    pub l3: Option<L3<'a>>,
}

pub fn parse_packet(input: &[u8]) -> Packet {
    let (input, l2) = parse_l2(input);
    let (input, l3) = match &l2 {
        L2::Unknown | L2::Error(_) => (input, None),
        L2::Ethernet(_) => {
            let (input, l3) = parse_l3(input);
            (input, Some(l3))
        }
    };
    Packet { l2, l3 }
}
