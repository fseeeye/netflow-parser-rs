#[derive(Debug, PartialEq)]
pub enum Error {
    Ethernet,
    Ipv4,
    Ipv6,
    Tcp,
    Udp,
    Modbus,
}
