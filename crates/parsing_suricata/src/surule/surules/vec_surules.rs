use crate::{
    surule::{TcpSurule, UdpSurule},
    SuruleParseError,
};

use super::Surules;

pub struct VecSurules {
    pub tcp_rules: Vec<TcpSurule>,
    pub udp_rules: Vec<UdpSurule>,
}

impl Surules for VecSurules {
    type Err = SuruleParseError;

    fn parse_from_file(_filepath: &str) -> Result<Self, Self::Err>
    where
        Self: Sized,
    {
        // TODO
        Ok(VecSurules {
            tcp_rules: vec![],
            udp_rules: vec![],
        })
    }
}
